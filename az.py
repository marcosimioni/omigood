#%%
from azure.identity import AzureCliCredential
from azure.mgmt import resource
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient

script = """
#!/bin/bash
MINVER=1.6.8.1
REGEX="OMI\-([0-9\.]*)\-"

# https://stackoverflow.com/questions/4023830/how-to-compare-two-strings-in-dot-separated-version-format-in-bash
vercomp () {
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

vercomp $MINVER $omi
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
#%%
credential = AzureCliCredential()
subscription_client = SubscriptionClient(credential)

#%%
for s in subscription_client.subscriptions.list():
    print(f'Checking subscription: {s.subscription_id}')
    resourcemanagement_client = ResourceManagementClient(credential, s.subscription_id)
    for rg in resourcemanagement_client.resource_groups.list():
        print(f'Checking Resource Group {rg.name}')
#%%
        for r in resourcemanagement_client.resources.list_by_resource_group(rg.name):
            if(r.type != 'Microsoft.Compute/virtualMachines'):
                continue
            cm = ComputeManagementClient(credential, s.subscription_id)
            nm = NetworkManagementClient(credential, s.subscription_id)
            vm = cm.virtual_machines.get(rg.name, r.name)
            if not vm.os_profile.linux_configuration:
                continue  # not Linux
            print(f'Found Linux VM: {r.name} with id {r.id}')

            vm_ext = cm.virtual_machine_extensions.list(rg.name, r.name)
            for n in  vm.network_profile.network_interfaces:
                print(f'Network interface name is: {n.id.split("/")[-1]}')
                x = nm.network_interfaces.get(rg.name, n.id.split('/')[-1])
                print(f'\tIP Configurations:')
                for i in x.ip_configurations:
                    print(f'\t\tPrivate IP: {i.private_ip_address}')
                    if i.public_ip_address:
                        public_ip = nm.public_ip_addresses.get(rg.name, x.ip_configurations[0].public_ip_address.id.split('/')[-1])
                    x.ip_configurations[0].public_ip_address.id.split('/')[-1]
                    print(f'\t\tPublic IP: {public_ip.ip_address}')
                sp = nm.network_security_groups.get(rg.name, x.network_security_group.id.split('/')[-1] )
                print('\tNetwork Security Rules:')
                for rule in sp.security_rules:
                    print(f'\t\t{rule.direction} {rule.protocol} {rule.access} from {rule.source_address_prefix},{",".join(rule.source_address_prefixes)} ports {rule.source_port_range},{",".join(rule.source_port_ranges)} to {rule.destination_address_prefix},{",".join(rule.destination_address_prefixes)} ports {rule.destination_port_range},{",".join(rule.destination_port_ranges)}')
                print(f'\tMAC Address: {x.mac_address}')
            if len(vm_ext.value) > 0:
                print('VM Extensions:')
                for e in vm_ext.value:
                    print(f'\tExtension: {e.name}')
            # Run the command
            print(f'Running the command...')
            run_command_parameters = {
                'command_id': 'RunShellScript', 
                'script': script.split('\n')
            }
            poller = cm.virtual_machines.begin_run_command(
                    rg.name,
                    r.name,
                    run_command_parameters
            )
            result = poller.result()  
            message = result.value[0].message
            print(f'Message is: {message}')
            if 'VULNERABLE' in message:
                print('MACHINE IS VULNERABLE!')

