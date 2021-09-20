# omigood (OM I GOOD?)

This repository contains a free scanner to detect VMs vulnerable to one of the "OMIGOD" vulnerabilities discovered by Wiz's threat research team, specifically **CVE-2021-38647**.

Original blog post from Wiz: https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure


## Overview

The scanner requires Azure credentials to connect to Azure APIs and, given a subscription and a resource group (or by default it will scan all the available ones), retrieves the list of Linux VMs and reports whether the machine might be vulnerable.

Also make sure to check out Microsoft's own tool for this purpose: https://github.com/microsoft/OMS-Agent-for-Linux/tree/master/tools/OMIcheck

## Authentication

To authenticate against Azure APIs, both `azure cli` (default) and Interactive Browser authentication are supported, check the `--auth` command line parameter.

## Performed checks

There isn't a straightforward way to determine whether your machines are vulnerable to OMI without running commands on the Linux machine itself, which is supported through Azure APIs using the `RunShellScript` command through an extension. Microsoft's own tool (https://github.com/microsoft/OMS-Agent-for-Linux/tree/master/tools/OMIcheck) uses this approach as well.

It's worth noting that, even if the VM is vulnerable, it might not be exposing the OMI server via HTTP/HTTPS (which is the default) and, even if it does, those ports might be blocked by Azure's Network Security Groups, hence not reachable. This is not a reason to avoid patching but, if you have a lot of vulnerable Linux VMs, it might be useful to know which ones are more exposed and prioritize your efforts.

`omigood` follows this approach and will produce a JSON output with a number of checks that you can trigger through command line options in order to determine your attack surface.

These are the checks performed by `omigood`:
 - Check against Azure API if the VM is running Linux
 - Check against Azure API if the VM is running the OMSAgentForLinux extension, which is a good hint on whether the machine might be running OMI as well.
 - Check against Azure API the version of the OMS Agent, as it is often correlated to the OMI version. This check can be performed without running any script on the VM. OMS Agent should be at least version `1.13.40`.
 - Check against Azure API the Network Security Groups of the VM, and determine (using a very simple algorithm that can trigger false positives) whether the OMI server ports might be open.
 - Check against Azure API the Effective Network Security Groups of the VM (combination of network interface and subnet) and determine whether the OMI server ports might be open. **This check is optional as it requires the VM to be running, higher API privileges and it takes more time to run. Enable it with the `-e` command line option.**
 - Use the Azure API to run a simple bash script on the VM that determines whether the OMI server is running, its version and whether it's exposed only on UNIX socket (default) or also TCP. **This check is optional as it requires the VM to be running, higher API privileges and it takes more time to run. Enable it with the `-r` command line option. Use at your own risk!**
 - Try to attack the machine's public IP running the `/usr/bin/id` command. **This check is optional as it involves trying to exploit the VM. Enable it with the `-a` command line option. Use it only on targets that you are authorized to test. Use it at your own risk!**

## Output

The generated JSON output file contains all the information on the scanned VMs: IDs, operating system, network security groups, power state, etc.

The flags ('YES'/'NO') that are relevant for the checks are:
  - *check_oms_extension*: `YES` if OMS Agent Extension is found on the VM.
  - *check_oms_vulnerable*: `YES` if OMS Agent Extension version is lower than `1.13.40`. 
  - *check_permissive_rules*: `YES` if Network Security Group rules seem to permit connections to OMI ports.
  - *check_permissive_effective_rules*: `YES` if Effective Security rules seem to permit connections to OMI ports. Only with `-e` command line option.
  - *check_omi_vulnerable*: `YES` if OMI server version was retrieved via script and determined to be lower than `1.6.8-1`. Only with `-r` command line option.
  - *check_omi_listening_on_tcp*: `YES` if OMI server status was retrieved via script and determined to be listening on TCP and not only UNIX sockets. Only with `-r` command line option.
  - *check_attack_successful*: `YES` if the attack on the VM's Public IP was successful. Only with `-r` command line option.

## Usage

```
usage: omigood_scanner.py [-h] [-v] [--auth {azurecli,interactivebrowser}] [-r] [-a] [-e] [-s SUBSCRIPTIONS]
                          [-g RESOURCEGROUPS] -o OUTPUT

OMIGood scanner for CVE-2021-38647

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         [OPTIONAL] Verbose mode: Displays additional debug details.
  --auth {azurecli,interactivebrowser}
                        Authentication mode. Default: azurecli.
  -r, --runscript       [OPTIONAL] Run Script. Runs bash script on target VMs to check for OMI server, agent and
                        version. Disabled by default. Use at your own risk.
  -a, --attack          [OPTIONAL] Try to attack the host. Disabled by default. Use at your own risk.
  -e, --effective       [OPTIONAL] Check Effective Security Rules. Disabled by default. Requires higher permissions on
                        Azure.
  -s SUBSCRIPTIONS, --subscriptions SUBSCRIPTIONS
                        [OPTIONAL] Comma separate list of subscriptions IDs. If not specified, it will try all.
  -g RESOURCEGROUPS, --resourcegroups RESOURCEGROUPS
                        [OPTIONAL] Comma separated list of Resource Group names. If not specified, it will try all. If
                        specified, it will work only with a single subscription provided.
  -o OUTPUT, --output OUTPUT
                        JSON output file with results.
```

## Contributors

- Marco Simioni
- Francesco Vigo
- Giordano Bianchi