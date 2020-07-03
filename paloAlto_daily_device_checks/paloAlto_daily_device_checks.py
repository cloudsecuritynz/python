import requests, json, re, datetime, logging, xmltodict



def pa_daily_checks(devices, DCs):
    '''
    Uses XML API to query various device stats to be used as part of
    daily network device checks. Designed to be used on hardware gateways and
    virtual Panoramas running v9.x . Returns formatted string for use in
    body of email.

    Functionality:
    Panorama:
    -collects device info - hostname, model, uptime
    -collects HA status - connectivity and status
    -collects Device Group status - connectivity and uptime
    -collects Log Collector status, connectivity, sync status
    -collects current CPU utilisation
    Gateways:
    -collects device info - hostname, model, uptime
    -collects HA status - connectivity and status and peer status
    -collects Fan and PSU status
    -collects SSL/TLS cert expiry details
    -collects current CPU utilisation
    -collects interface/aggregate interface status

    Internal Function:
    _pa_api_request(host, request, APIKey) - created for reusability for
    various API calls

    Parameters:
    devices - dictionary of device details, containing host IP and API Key
    DC's - list of configured Palo Alto data centre objects

    Exceptions:
    exceptions are caught for any API call fails and indicative error added
    to return string for further investigation

    Returns:
    dictionary deviceInfo, dictionary of Palo Alto devices with keys being device
    IPs and values being dictionaries of device data retrieved from API.
    '''

    today = datetime.date.today()
    day = today.strftime("%d_%m_%Y")

    #specify all API paths
    panFwDeviceType = "/api/?type=op&cmd=<show><system><info></info></system></show>"
    panHaStatus = "/api/?type=op&cmd=<show><high-availability><state></state></high-availability></show>"
    panDeviceGroups = "/api/?type=op&cmd=<show><devicegroups></devicegroups></show>"
    panManagedCollectors = "/api/?type=op&cmd=<show><log-collector><connected></connected></log-collector></show>"
    panFwSysResources = "/api/?type=op&cmd=<show><system><resources></resources></system></show>"
    fwHaStatus = "/api/?type=op&cmd=<show><high-availability><state></state></high-availability></show>"
    fwCerts = "/api/?type=op&cmd=<show><sslmgr-store><config-certificate-info></config-certificate-info></sslmgr-store></show>"
    fwEnv = "/api/?type=op&cmd=<show><system><environmentals></environmentals></system></show>"
    fwInts = "/api/?type=op&cmd=<show><interface>all</interface></show>"

    #define a dictionary to store device info
    deviceInfo = {}
    dc = ""
    #internal method to make API calls to PA device
    def _pa_api_request(host, request, APIKey):
        apiKey = {"X-PAN-KEY" : APIKey}
        url = "https://"+host+request
        try:
            resp = requests.get(url, headers=apiKey, verify=False)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            #any other errors, send email alert and abort
            logging.debug(f'DEBUG _pa_api_request {url} failed error: {e}')
            status = f'ERROR _pa_api_request {url} failed error: {e}'
        else:
            statusCode = resp.status_code
            if int(statusCode) in range(200, 230):
                status = resp.text
            else:
                status = resp
        return status

    #loop through all devices passed as arguments and collect device info
    for k,v in devices.items():
        #create nested dictionary per device and populate with device details
        deviceInfo[k] = {}
        firstRequest = _pa_api_request(k, panFwDeviceType, v)

        #if api request is exception or not http status 200-230, record error
        if str(firstRequest).startswith('ERROR') or str(firstRequest).startswith('<Res'):
             deviceInfo[k].update({"error" : firstRequest})
        #if api request successful, collect data
        else:
            #get device hostname, uptime and model (eg Panorama or gateway)
            reqDeviceType = xmltodict.parse(firstRequest)
            deviceInfo[k].update({"hostname" : reqDeviceType["response"]["result"]["system"]["hostname"]})
            deviceInfo[k].update({"uptime" : reqDeviceType["response"]["result"]["system"]["uptime"]})
            deviceInfo[k].update({"model" : reqDeviceType["response"]["result"]["system"]["model"]})
            if deviceInfo[k]["model"] == "Panorama":
                #get status details for Panorama devices
                reqPanHA = xmltodict.parse(_pa_api_request(k, panHaStatus, v))
                reqPanDG = xmltodict.parse(_pa_api_request(k, panDeviceGroups, v))
                reqPanMC = xmltodict.parse(_pa_api_request(k, panManagedCollectors, v))
                deviceInfo[k].update({"hastatus" : reqPanHA["response"]["result"]["local-info"]["state"]})
                deviceInfo[k].update({"haconnstatus" : reqPanHA["response"]["result"]["peer-info"]["conn-status"]})
                for i in reqPanDG["response"]["result"]["devicegroups"]["entry"]:
                    dc = i['@name']
                    if dc in DCs:
                        hostname = ""
                        for num in range (0,2):
                            #loop through and get device group info
                            for kki,vv in i["devices"]["entry"][num].items():
                                if kki == "hostname":
                                    hostname = vv
                                    deviceInfo[k].update({dc+"dghostname"+hostname : vv})
                            for kkk,vvv in i["devices"]["entry"][num].items():
                                if kkk == "connected":
                                    deviceInfo[k].update({dc+"dgconnected"+hostname : vvv})
                                if kkk == "uptime":
                                    deviceInfo[k].update({dc+"dguptime"+hostname : vvv})
                #collect log collector info
                for l in reqPanMC["response"]["result"]["log-collector"]["entry"]:
                    hostname = l["host-name"]
                    deviceInfo[k].update({hostname+"mchostname" : l["host-name"]})
                    deviceInfo[k].update({hostname+"mcconnected" : l["connected"]})
                    deviceInfo[k].update({hostname+"mcinsync" : l["config-status"]})
                    deviceInfo[k].update({hostname+"mcinterlcstatus" : l["interlc-status"]})
                    deviceInfo[k].update({hostname+"mcinterlcmsg" : l["interlc-msg"]})
            else:
                #get status details for PA firewalls
                reqFwHA = xmltodict.parse(_pa_api_request(k, fwHaStatus, v))
                reqFwCerts = xmltodict.parse(_pa_api_request(k, fwCerts, v))
                reqFwEnv = xmltodict.parse(_pa_api_request(k, fwEnv, v))
                reqFwInts = xmltodict.parse(_pa_api_request(k, fwInts, v))
                deviceInfo[k].update({"hastate" : reqFwHA["response"]["result"]["group"]["local-info"]["state"]})
                deviceInfo[k].update({"hasyncstate" : reqFwHA["response"]["result"]["group"]["local-info"]["state-sync"]})
                deviceInfo[k].update({"hadurationstate" : reqFwHA["response"]["result"]["group"]["local-info"]["state-duration"]})
                deviceInfo[k].update({"peerconnmgmtstatus" : reqFwHA["response"]["result"]["group"]["peer-info"]["conn-mgmt"]["conn-status"]})
                deviceInfo[k].update({"peerconnstatus" : reqFwHA["response"]["result"]["group"]["peer-info"]["conn-status"]})
                deviceInfo[k].update({"peerconnha2status" : reqFwHA["response"]["result"]["group"]["peer-info"]["conn-ha2"]["conn-status"]})
                deviceInfo[k].update({"peerconnha1status" : reqFwHA["response"]["result"]["group"]["peer-info"]["conn-ha1"]["conn-status"]})
                deviceInfo[k].update({"peerconnha2backupstatus" : reqFwHA["response"]["result"]["group"]["peer-info"]["conn-ha2-backup"]["conn-status"]})
                deviceInfo[k].update({"peerconnha1backupstatus" : reqFwHA["response"]["result"]["group"]["peer-info"]["conn-ha1-backup"]["conn-status"]})

                #get psu status - any alarms
                envs = reqFwEnv["response"]["result"]["power-supply"]["Slot1"]["entry"]
                num = 0
                for items in envs:
                    for attrib in items:
                        if attrib == "alarm":
                            num += 1
                            deviceInfo[k].update({"psu"+str(num)+"alarm" : items[attrib]})
                #get fan status - any alarms
                envs = reqFwEnv["response"]["result"]["fan"]["Slot1"]["entry"]
                num = 0
                for items in envs:
                    for attrib in items:
                        if attrib == "alarm":
                            num += 1
                            deviceInfo[k].update({"fan"+str(num)+"alarm" : items[attrib]})

                #get cert status - store expiry and name
                certs = reqFwCerts["response"]["result"]
                certs = re.sub(': ', ':', certs)
                certs = re.sub(r'\s+', ' ', certs)
                certs = re.sub('\\n', '', certs)
                certExpireRegex = r'exp-date:(\w*\()(((\w*\s*)+(:\d+)+)(\s*\w*)+)'
                certNameRegex = r'(db-name:(/(\w*)=.*?)\sdb)'
                sslcertexpiry, sslcertname = [], []
                sslcertexpiry = re.findall(certExpireRegex, certs)
                sslcertname = re.findall(certNameRegex, certs)
                logging.debug(f'#############{sslcertname}')
                for cert in range(0,len(sslcertexpiry)):
                    deviceInfo[k].update({"sslcertname"+str(cert+1) : sslcertname[cert][1]})
                    deviceInfo[k].update({"sslcertexpiry"+str(cert+1) : sslcertexpiry[cert][1]})

                #get interface and aggregate interface status
                intf, agg = 1, 1
                for key,value in reqFwInts["response"]["result"]["hw"].items():
                    for interface in value:
                        if interface["state"] == "up" and interface["type"] == "0":
                            deviceInfo[k].update({"if_"+str(intf) : interface["name"]})
                            intf += 1
                        if interface["state"] == "up" and interface["type"] == "1":
                            deviceInfo[k].update({"ag_"+str(agg) : interface["name"]})
                            agg += 1

            #get CPU info for all devices, Panormama or Gateway
            reqPanFwSysResources = xmltodict.parse(_pa_api_request(k, panFwSysResources, v))
            resources = reqPanFwSysResources["response"]["result"]
            cpuRegex = r'((\d+)\.\d+)\sid'
            cpu = re.search(cpuRegex, resources)
            cpu = float(cpu.group(1))
            cpu = str(round(100 - cpu))+"%"
            deviceInfo[k].update({"cpuusage" : cpu})
    logging.debug(f'\nDEBUG deviceInfo  =============')
    return deviceInfo


def pa_daily_checks_format(deviceInfo):
    '''
    takes deviceInfo dict from pa_daily_checks() function and creates a formatted
    return string to be used to display data in body of email

    Parameters:
    deviceInfo - dictionary of Palo Alto devices with keys being device IPs and
    values being dictionaries of device data retrieved from API.

    Returns:
    panorama string formats any panorama data into string for use in body of email.
    pa string formats any Palo Alto gateway data into string for use in body of
    email. Strings concantenated and returned.
    '''
    panorama = ""
    pa = ""
    doubleDashedLine = "\n=========================="
    dashedLine = "\n-------------------------"
    starredLine = "\n***************************"

    #loop through devices in deviceInfo dict and create return strings
    for k,v in deviceInfo.items():
        if 'error' in v:
            panorama += starredLine+"\nError connecting to "+k+":\n\t"+v['error']+starredLine
        else:
            #if device is Panorama, collect data and add to panorama string
            if v["model"] == "Panorama":
                panorama += "\n"+doubleDashedLine+"\nFirewall - PANORAMA"+doubleDashedLine
                panorama += "\n"+v["hostname"]+" | uptime: "+v["uptime"]+dashedLine
                panorama += "\nHA Status: "+v["hastatus"].upper()+" | "+v["haconnstatus"].upper()
                panorama += "\nDevice Groups DC1:"
                panorama += "\n\t"+v["DC1dghostnameLTHAMFW01"]+" | connected: "+v["DC1dgconnectedLTHAMFW01"]+" | uptime: "+v["DC1dguptimeLTHAMFW01"]
                panorama += "\n\t"+v["DC1dghostnameLTHAMFW02"]+" | connected: "+v["DC1dgconnectedLTHAMFW02"]+" | uptime: "+v["DC1dguptimeLTHAMFW02"]
                panorama += "\nDevice Groups DC2:"
                panorama += "\n\t"+v["DC2dghostnameLTORBFW01"]+" | connected: "+v["DC2dgconnectedLTORBFW01"]+" | uptime: "+v["DC2dguptimeLTORBFW01"]
                panorama += "\n\t"+v["DC2dghostnameLTORBFW02"]+" | connected: "+v["DC2dgconnectedLTORBFW02"]+" | uptime: "+v["DC2dguptimeLTORBFW02"]
                panorama += "\nManaged Collectors:"
                panorama += "\n\t"+v["DC1PANmchostname"]+"\n\t\tConnected: "+v["DC1PANmcconnected"]+ \
                "\n\t\tSync Status: "+v["DC1PANmcinsync"]+"\n\t\tLog Collector Status: "+v["DC1PANmcinterlcstatus"]+ \
                "\n\t\tLog Collector Status Message: "+v["DC1PANmcinterlcmsg"]
                panorama += "\n\t"+v["DC2PANmchostname"]+"\n\t\tConnected: "+v["DC2PANmcconnected"]+ \
                "\n\t\tSync Status: "+v["DC2PANmcinsync"]+"\n\t\tLog Collector Status: "+v["DC2PANmcinterlcstatus"]+ \
                "\n\t\tLog Collector Status Message: "+v["DC2PANmcinterlcmsg"]
                panorama += "\nCPU Usage: "+v["cpuusage"]
            #if device is Palo Alto gateway, collect data and add to pa string
            else:
                pa += "\n"+doubleDashedLine+"\nFirewall - Palo Alto"+doubleDashedLine
                pa += "\n"+v["hostname"]+" | model: "+v["model"]+" | uptime: "+v["uptime"]+dashedLine
                pa += "\nHA Status: "+v["hastate"].upper()+" | Sync"+v["hasyncstate"]
                pa += "\nHA Links Status: "+v["peerconnmgmtstatus"].upper()+" | Sync"+v["hasyncstate"]
                pa += "\nHardware Status:"
                psus, fans, ifc, ag = 0, 0, 0, 0
                for key in v.keys():
                    if key.startswith("psu"): psus +=1
                    if key.startswith("fan"): fans +=1
                    if key.startswith("if_"): ifc +=1
                    if key.startswith("ag_"): ag +=1
                for p in range(1,psus+1):
                    if v["psu"+str(p)+"alarm"] == "False":
                        pa += "\n\tPower Supply "+str(p)+": OK"
                    else:
                        pa += "\n\tPower Supply "+str(p)+": !!!ALARM!!!"
                for f in range(1,fans+1):
                    if v["fan"+str(f)+"alarm"] == "False":
                        pa += "\n\tFan "+str(f)+": OK"
                    else:
                        pa += "\n\tFan "+str(f)+": !!!ALARM!!!"
                pa += dashedLine+"\nInterfaces"+dashedLine
                for i in range(1,ifc+1):
                    pa += "\n\tInterface "+v["if_"+str(i)]+": UP"
                for a in range(1,ag+1):
                    pa += "\n\tAggregate Interface "+v["ag_"+str(a)]+": UP"
                pa += dashedLine+"\nSSL Certificate Status"
                sslcerts, sslexpiry = 0, 0
                for key in v.keys():
                    if key.startswith("sslcertname"): sslcerts +=1
                    if key.startswith("sslcertexp"): sslexpiry +=1
                if sslcerts == sslexpiry:
                    for cert in range(1,sslcerts+1):
                        pa += "\n\tCertificate: "+v["sslcertname"+str(cert)].split("=")[-1]+", Expires: "+v["sslcertexpiry"+str(cert)]
                pa += "\nCPU Usage: "+v["cpuusage"]

    return panorama+pa
    
    
if __name__ == "__main__":
    DCs = ["DC1", "DC2"]
    devices = {IP : APIKey, IP2 : APIKey2, IP3 : APIKey3, IP4 : APIKey4}
    pas = pa_daily_checks_format(pa_daily_checks(devices, DCs))
