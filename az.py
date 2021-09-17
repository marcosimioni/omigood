import sys
import logging
import re
import argparse
import traceback
from typing import Dict, List, Optional, Any

from azure.identity import AzureCliCredential
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
MIN_PATCHED_OMI_VERSION = "1.6.8.1"

BASH_SCRIPT = """
#!/bin/bash
MINVERSION=1.6.8.1
REGEX="OMI\-([0-9\.]*)\-"

# https://stackoverflow.com/questions/4023830/how-to-compare-two-strings-in-dot-separated-version-format-in-bash
version_compare () {
    if [[ $1 == $2 ]]
    then
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    # fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
    do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++))
    do
        if [[ -z ${ver2[i]} ]]
        then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]}))
        then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]}))
        then
            return 2
        fi
    done
    return 0
}

OMIPATH="/opt/omi/bin/omiserver"
if ! [[ -x $OMIPATH ]]; then
        echo "OMI not found"
        exit 0
fi
OMIVERSION=$($OMIPATH --version)


if ! [[ $OMIVERSION =~ $REGEX ]];
then
        echo "Cannot detect OMI version"
        exit 2
else
        omi=${BASH_REMATCH[1]}
fi
echo -n "OMI version: $omi..."

version_compare $MINVERSION $omi
case $? in
        0) op=0;;
        1) op=1;;
        2) op=0;;
esac

if [[ $op == 1 ]]; then
        echo "VULNERABLE!"
else
        echo "OK!"
fi
exit $op
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
    logger.info(f"Running Shell script on VM {vm_name} to determine OMI status...")
    params = {"command_id": "RunShellScript", "script": script.split("\n")}
    poller = cm.virtual_machines.begin_run_command(resource_group_name, vm_name, params)
    result = poller.result()
    if not result or not result.value or not result.value[0].message:
        logger.error(f"Cannot get result after running script on VM: {vm_name}")
    message = result.value[0].message
    logger.debug(f"Output from script on VM {vm_name}: {message}")
    return message


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
            intf_config_string += print_rules(
                vm_interface["nsg_rules"], "Network Security Rules"
            )
        # Effective Security Rules
        if check_effective:
            vm_interface["effective_rules"] = check_effective_security_rules(
                nm, interface_info, vm_name
            )
            intf_config_string += print_rules(
                vm_interface["effective_rules"], "Effective Security Rules"
            )
        logger.info(intf_config_string)
        vm_interfaces.append(vm_interface)
    return vm_interfaces


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
                # do the attack
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
            " Requires more permissins on Azure."
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

    try:
        args = parser.parse_args()
        if args.verbose:
            logger.setLevel(logging.DEBUG)
            log_handler.setLevel(logging.DEBUG)

        credential = AzureCliCredential()
        subscription_client = SubscriptionClient(credential)

        subs_to_check = []
        if args.subscriptions:
            subs_to_check = args.subscriptions.split(",")
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

        rgs_to_check = []
        if args.resourcegroups:
            rgs_to_check = args.resourcegroups.split(",")

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
                for r in rm.resources.list_by_resource_group(rg.name):
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
                    if vm.network_profile:
                        vm_interfaces = check_vm_netsec(
                            nm, r.name, vm.network_profile, args.effective
                        )
                    vm_extensions = retrieve_vm_extensions(cm, rg.name, r.name)
                    if args.runscript:
                        message = run_script_on_vm(cm, rg.name, r.name, BASH_SCRIPT)
                        if "VULNERABLE" in message:
                            logger.info("MACHINE IS VULNERABLE!")
                        else:
                            logger.info("MACHINE IS NOT VULNERABLE")
                    if args.attack:
                        vulnerable = attack_vm(r.name, vm_interfaces)
                        if vulnerable:
                            logger.info("MACHINE IS VULNERABLE")
                        else:
                            logger.info("MACHINE IS NOT VULNERABLE")

    except Exception as e:
        logger.error(
            f"Got Exception, exiting!\nException: {str(e)}\n{traceback.format_exc()}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
