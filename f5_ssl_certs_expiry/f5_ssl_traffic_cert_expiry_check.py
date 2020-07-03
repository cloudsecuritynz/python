import requests, json, re, datetime, logging, os
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
from netmiko.ssh_exception import NetMikoAuthenticationException
logging.basicConfig(level=logging.DEBUG, format="{asctime} {processName:<12} \
{message} ({filename}:{lineno})", style="{")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def ssl_cert_expiry(deviceDetails):
    """
    Check F5 device for SSL traffic certs (NOT device certs) that expire in next XX days

    Note: F5 v11.x.x 'check-certs' utility doesnt work, hence netmiko used.
    Tested against: v11.6.5, v14.1.2.3, v14.1.2.6

    Functionality:
    -Makes SSH (using netmiko) call to defined F5 to get SSL cert info. Output
    line containing expiry info inserted into list certExpiryDays
    -Makes second call to F5 device to retrieve line of output containing cert
    names, which is inserted into list certName as string
    -cert expiry in days calculated and any above threshold (ie 31 days) are
    returned as a string

    Parameters:
    deviceDetails - dictionary, continaing target F5 details - as per netmiko docco

    Exceptions:
    -exceptions are caught for any netmiko connections

    Returns:
    succesful SSH call and parsing will return a string detailing those certs
    due to expire within threshold days.
    """
    #GET hostname of the device from api call
    path = "/mgmt/tm/sys/global-settings/?$select=hostname"
    url = "https://"+deviceDetails["host"]+path
    try:
        resp = requests.get(url, auth=(deviceDetails["username"], deviceDetails["password"]), verify=False)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.debug(f'DEBUG GET request {path} failed error: {e}')
        hostname = f'Host {host} api failed to get hostname'
    else:
        hostname = json.loads(resp.text)["hostname"].split('.')[0]

    certExpiryDays = []
    dashedLine = "\n-------------------------"
    entry = dashedLine+"\nLTM SSL Cert Expiry "+hostname.upper()+dashedLine
    status, expired = "", ""
    expiryDict = {}
    now = datetime.datetime.now()
    commandExpire = "tmsh list sys crypto cert |grep -e expiration"
    commandCertName = "tmsh list sys crypto cert |grep -e crypto"

    #internal function to make ssh call using netmiko, passed device dict and command
    def _sshConnection(device, command):
        try:
            net_connect = ConnectHandler(**device)
            output = net_connect.send_command(command)
        except (NetMikoTimeoutException, NetMikoAuthenticationException):
            output = f"ERROR with netmiko ucs list call. Command = {command}"
        return output

    #connect to F5 device via SSH and get cert expiry line of output and
    # insert into list certExpiryDays as string
    output = _sshConnection(deviceDetails, commandExpire)
    logging.debug(f'DEBUG netmiko certExpiry {output}')
    if output.rfind("expiration", 3, 15) == 4:
        certExpiryDays = output.split("\n")
    else:
        status = output

    #for certs within expiry range (62 days) - get expiry number in days and add as
    #value to expiryDict with index number from certExpiryDays list as the key
    if not status:
        counter = 0
        for w in certExpiryDays:
            #compare cery expiry in days to current date
            monDT = datetime.datetime.strptime(w[15:18], "%b")
            diff =  datetime.datetime(int(w[-9:-4]), monDT.month, int(w[19:21])) - now
            #Change exipry days threshold here
            if diff.days < 62 and diff.days > 0 :
                expiryDict[counter] = diff.days
            counter += 1

    #make a new ssh call and this time save each output line containing cert names to
    #list certName. The key of expiryDict is the index number of list
    #certName and is used to connect the cert name and the days until expiry
    if expiryDict:
        output = _sshConnection(deviceDetails, commandCertName)
        if output.rfind("crypto", 4, 10) == 4:
            certName = output.split("\n")
            for k,v in expiryDict.items():
                status += " "+certName[k].split(" ")[3]+" expires in "+str(v)+" Days\n"

    if not status:
        status = entry+"\nNo SSL certs expiring within the next 62 days"
    else:
        status = entry+"\n"+status

    return status
    
if __name__ == "__main__":
    ltm1 = { 'device_type': 'f5_linux', #for use in netmiko request
           'host' : '1.2.3.4',
           'username' : 'admin',
           'password' : 's0m3P@ssw0rd'}
    f51 = ssl_cert_expiry(ltm1)
