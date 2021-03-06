import requests, json, re, datetime, logging
  
def f5_daily_checks(host, username, password):
    '''
    Uses iControl API to query various device stats to be used as part of
    daily network device checks. Designed to be used on hardware running v12.x -
    v14.x. Returns formatted string for use in body of email.

    Functionality:
    -gets hostname
    -collects health status, active, online
    -collects current memory usage (TMM)
    -collects latest 5 min avergae CPU usage for all cpu's
    -collects interface status and lists those which are UP
    -collects all fan and psu status'
    -collects temp or F5 chassis
    -collects GTM/DNS DC status (ie available/unavailable)
    -collects GTM/DNS server object status (ie available/unavailable)

    Internal Function:
    _api_request(host, path, username, password) - created for reusability for
    various API calls

    Parameters:
    host - string, ip address of F5
    username - string
    password - string

    Exceptions:
    exceptions are caught for any API call fails and indicative error added
    to return string for further investigation

    Returns:
    string result collects these results and forms the body of the email
    '''

    #GET hostname of the device from api call
    path = "/mgmt/tm/sys/global-settings/?$select=hostname"
    url = "https://"+host+path
    try:
        resp = requests.get(url, auth=(username, password), verify=False)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.debug(f'DEBUG GET request {path} failed error: {e}')
        hostname = f'Host {host} api failed to get hostname'
    else:
        hostname = json.loads(resp.text)["hostname"].split('.')[0]

    #dashed lines for formatting result string which forms body of email
    dashedLine = "\n--------------------------"
    doubleDashedLine = "\n=========================="

    #result string holds formatted text to be displayed in the body of the email
    result = doubleDashedLine+"\n"+hostname.upper()+doubleDashedLine
    hostname = host

    #internal function to make API calls
    def _api_request(host, path, username, password):
        status = ""
        url = "https://"+host+path
        try:
            resp = requests.get(url, auth=(username, password), verify=False)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            #any other errors, alert and add info to status string
            logging.debug(f'DEBUG GET request {path} failed error: {e}')
            status = f'ERROR GET request {path} failed: {e}'
        else:
            statusCode = resp.status_code
            if statusCode in range(200,230):
                status = resp.text
            else:
                status = resp
        return status


    #check if F5 unit online/healthy/active
    pathHealth = "/mgmt/tm/cm/failover-status"
    response = _api_request(host, pathHealth, username, password)
    if not response.startswith('ERROR'):
        logging.debug(f'RESPONSE F5 unit health = {response}')
        responseDict = (json.loads(response))["entries"] \
        ["https://localhost/mgmt/tm/cm/failover-status/0"] \
        ["nestedStats"]["entries"]
        color = responseDict["color"]["description"]
        status = responseDict["status"]["description"]
        summary = responseDict["summary"]["description"]
        result += f"\nDevice Status: {color.upper()}, {status}, {summary}{dashedLine}"
    else:
        result += "\nError getting device Health/Active Status"


    #check F5 memory status - current % usage
    pathMemTotal = "/mgmt/tm/sys/host-info?$select=memoryTotal"
    pathMemUsed = "/mgmt/tm/sys/host-info?$select=memoryUsed"
    responseMemTotal = _api_request(host, pathMemTotal, username, password)
    responseMemUsed = _api_request(host, pathMemUsed, username, password)
    if not responseMemUsed.startswith('ERROR') and not responseMemTotal.startswith('ERROR'):
        logging.debug(f'RESPONSE F5 memory usage = {responseMemTotal} {responseMemTotal}')
        responseMemTotalStr = (json.loads(responseMemTotal))["entries"] \
        ["https://localhost/mgmt/tm/sys/host-info/0"]["nestedStats"]["entries"] \
        ["memoryTotal"]["value"]
        responseMemUsedStr = (json.loads(responseMemUsed))["entries"] \
        ["https://localhost/mgmt/tm/sys/host-info/0"]["nestedStats"]["entries"] \
        ["memoryUsed"]["value"]
        result += f"\nResource Usage{dashedLine}\nCurrent Memory Usage: {round(int(responseMemUsedStr)/(0.01*int(responseMemTotalStr)))}%"
    else:
        result += "\nError getting memory usage"


    #check F5 CPU status - last 5 mins usage
    pathCpu = "/mgmt/tm/sys/cpu/stats"
    cpu =  {}
    responseCpu = _api_request(host, pathCpu, username, password)
    if not responseCpu.startswith('ERROR'):
        logging.debug(f'RESPONSE CPU stats = {responseCpu}')
        responseCpuDict = (json.loads(responseCpu))["entries"] \
        ["https://localhost/mgmt/tm/sys/cpu/0/stats"] \
        ["nestedStats"]["entries"]["https://localhost/mgmt/tm/sys/cpu/0/cpuInfo/stats"] \
        ["nestedStats"]["entries"]
        numCpus = len(responseCpuDict)
        #loop through CPUs and add 5min avg to result string
        for c in range(0, numCpus):
            cpu[c] = responseCpuDict["https://localhost/mgmt/tm/sys/cpu/0/cpuInfo/"+str(c)+"/stats"] \
            ["nestedStats"]["entries"]["fiveMinAvgIdle"]["value"]
            result += "\nCPU-"+str(c)+" (5 Min Avg) "+" "+str(100-(cpu[c]))+"%"
    else:
        result += "\nError getting CPU usage"

    #check F5 interface status
    pathInt = "/mgmt/tm/net/interface/stats"
    responseInt = _api_request(host, pathInt, username, password)
    if not responseCpu.startswith('ERROR'):
        logging.debug(f'RESPONSE Interface stats = {responseInt}')
        responseIntDict = json.loads(responseInt)['entries']
        interfaces = 0
        #loop through interfaces and add those with status 'up' to result string
        for k,v in responseIntDict.items():
            name  = v["nestedStats"]["entries"]["tmName"]["description"]
            intStatus = v["nestedStats"]["entries"]["status"]["description"]
            if intStatus == "up" and name != "mgmt":
                if interfaces == 0:
                    result += f'{dashedLine}\nInterface Status{dashedLine}'
                result += f"\nInterface {name} UP"
            interfaces += 1
    else:
        result += "\nError getting Interface status"


    #Check F5 hardware: Fans, PSU and Temp status
    pathHardware = "/mgmt/tm/sys/hardware/stats"
    tempHiLimit, tempCurrent = "", ""
    fans, psu = {}, {}
    responseHardware = _api_request(host, pathHardware, username, password)
    if not responseHardware.startswith('ERROR'):
        logging.debug(f'RESPONSE Hardware stats = {responseHardware}')
        responseFansDict = (json.loads(responseHardware))["entries"] \
        ["https://localhost/mgmt/tm/sys/hardware/chassis-fan-status-index/stats"] \
        ["nestedStats"]["entries"]
        numFans = len(responseFansDict)
        #loop through fans and add status to Fan dict
        for f in range(1, numFans+1):
            fans[f] = responseFansDict["https://localhost/mgmt/tm/sys/hardware/chassis-fan-status-index/"+str(f)+"/stats"] \
            ["nestedStats"]["entries"]["status"]["description"]
        responsePsuDict = (json.loads(responseHardware))["entries"] \
        ["https://localhost/mgmt/tm/sys/hardware/chassis-power-supply-status-index/stats"] \
        ["nestedStats"]["entries"]
        numPsu = len(responsePsuDict)
        #loop through PSU's and add status to PSU dict
        for p in range(1, numPsu+1):
            psu[p] = responsePsuDict["https://localhost/mgmt/tm/sys/hardware/chassis-power-supply-status-index/"+str(p)+"/stats"] \
            ["nestedStats"]["entries"]["status"]["description"]
        responseTempDict = (json.loads(responseHardware))["entries"] \
        ["https://localhost/mgmt/tm/sys/hardware/chassis-temperature-status-index/stats"] \
        ["nestedStats"]["entries"]["https://localhost/mgmt/tm/sys/hardware/chassis-temperature-status-index/1/stats"] \
        ["nestedStats"]["entries"]
        tempHiLimit = responseTempDict["hiLimit"]["value"]
        tempCurrent = responseTempDict["temperature"]["value"]
        #add values to result string
        result += dashedLine+"\nHardware Status"+dashedLine
        for i in range(1, len(fans)+1):
            result += "\nFan"+str(i)+" "+fans[i].upper()
        for j in range(1, len(psu)+1):
            result += "\nPSU"+str(j)+" "+psu[j].upper()
        result += "\nChassis Temp Max"+" "+str(tempHiLimit)+"C"
        result += "\nChassis Temp Current"+" "+str(tempCurrent)+"C"
    else:
        result += "\nError getting Fans/PSU/Temp status"


    #check GTM DCs status
    #adjust as necessary for number of DCs..
    DC1Status, DC2Status = "", ""
    pathDC1GtmStatus = "/mgmt/tm/gtm/datacenter/~Common~DC1/stats?$select=status.availabilityState"
    pathDC2GtmStatus = "/mgmt/tm/gtm/datacenter/~Common~DC2/stats?$select=status.availabilityState"
    responseDC1GtmStatus = _api_request(host, pathDC1GtmStatus, username, password)
    responseDC2GtmStatus = _api_request(host, pathDC2GtmStatus, username, password)
    if not responseDC1GtmStatus.startswith('ERROR') and not responseDC2GtmStatus.startswith('ERROR'):
        logging.debug(f'RESPONSE GTM DCs = {responseDC1GtmStatus}')
        DC1Status = json.loads(responseDC1GtmStatus)["entries"]["https://localhost/mgmt/tm/gtm/datacenter/~Common~DC1/stats"] \
        ["nestedStats"]["entries"]["status.availabilityState"]["description"]
        DC2Status = json.loads(responseDC2GtmStatus)["entries"]["https://localhost/mgmt/tm/gtm/datacenter/~Common~DC2/stats"] \
        ["nestedStats"]["entries"]["status.availabilityState"]["description"]
        result += dashedLine+"\nGTM/DNS Status"+dashedLine
        result +="\nDC1 GTM DC\t"+DC1Status.upper()+"\nDC2 GTM DC\t"+DC2Status.upper()
    else:
        result +="\nError getting GTM DC status"

    #check GTM Servers object status
    servers = {}
    pathGtmServers = "/mgmt/tm/gtm/server/stats"
    responseGtmServers = _api_request(host, pathGtmServers, username, password)
    if not responseGtmServers.startswith('ERROR'):
        logging.debug(f' RESPONSE GTM Servers = {responseGtmServers}')
        for k,v in (json.loads(responseGtmServers)["entries"]).items():
            server = re.search(r'(~([\w]+)/)', k)
            servers[server.group(2)] = v["nestedStats"]["entries"]["status.availabilityState"]["description"]
        for k,v in servers.items(): result += " \nGTM server *"+str(k)+"*\t"+str(v).upper()
    else:
        result += "\nError getting GTM Servers status"

    return result

if __name__ == "__main__":
    f51 = f5_daily_checks("IP", "username", "password")
    f51 = f5_daily_checks("IP", "username", "password")  

