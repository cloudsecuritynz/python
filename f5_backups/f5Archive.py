
#! python3.8
#git at cloudsecurity period nz
"""
F5 VERSION & RESOURCES:
Designed for F5 BIGIP iControl Version 14.1.2.3, YMMV for other versions
Reference Guide:https://cdn.f5.com/websites/devcentral.f5.com/
downloads/icontrol-rest-api-user-guide-14-1-0.pdf
Command examples: https://support.f5.com/csp/article/K13225405
"""
import requests, json, time, datetime, os, hashlib, logging, random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


logging.basicConfig(level=logging.DEBUG, format="{asctime} {processName:<12} \
{message} ({filename}:{lineno})", style="{")
logging.disable(logging.CRITICAL)

class F5Archive:
    """
    This class uses API calls with the requests module to create a UCS archive,
    download the archive, verify integrity of the downloaded file with checksums,
    download the f5 masterkey and delete any UCS files on the F5 older than X days.

    Methods:
    This Class has the following Methods:
    -generate_ucs - creates a ucs, first using simple POST request to
        /mgmt/tm/sys/ucs/ if that fails, or if user specifies that UCS will be large,
        an iControl asynchronous task to /mgmt/tm/task/sys/ucs is run to create UCS
        returns:
        -ucs name in format: 'hostname_YYYY-MM-DD_XXX.ucs' where XXX= random int
        -time taken to create UCS as string
    - download_ucs - downloads the ucs to local directory.
    - get_ucs_checksums - creates a checksum of the on box ucs and a checksum of the
        (same) downloaded ucs and compares them to verify no corruption in download
    - get_f5mk - gets the F5 configuration masterkey, compares it to that stored in
        local file and appends if different. Useful for standalone F5 deployments.
    - cleanup_ucs - creates a list of UCS' on box and deletes any older than X days

    Instance Attributes:
    The following attributes are instantiated for use by the different methods:
    -self.F5IP - the IP or hostname of the target F5 device
    -self.username - username used to authenticate to the target F5
    -self.password - password used to authenticate to the target F5

    """

    def __init__(self, F5IP, username, password):
        self.F5IP = F5IP
        self.username = username
        self.password = password
        self.ucsDir = os.getcwd()+"\\F5Backups\\"

    def generate_ucs(self, isLarge=False):
        """
        Creates a UCS archive on the F5

        Functionality:
        -Makes an API call to get the hostname
        -Makes an API call to create the UCS name based off the hostname, the
        date and a random integer.
        -If 'isLarge' parameter default (false), then an API call will be made to
        generate UCS using a basic POST call. This is for smaller UCS files as
        iControl calls can timeout around 60 seconds whilst UCS is being generated.
        -If basic POST call fails, or if isLarge=True, a new API call will be
        made to create an asynchronous task to generate the ucs. iControl API
        asynchronous tasks are not subject to the same API call timeouts as
        non-task POST iControl calls.

        Attributes:
        The following instance attributes are used in API calls:
        -self.F5IP
        -self.username
        -self.password

        Parameters:
        islarge - boolean, indicates that asynchronous task should be used to
        download the UCS archive. Default=False

        Exceptions:
        exceptions are caught for an requests module API calls and stored as
        a string to be returned for error logging

        Returns:
        succesful UCS creation will return a string containing name of the UCS file
        and the time it took to create. If unsuccessful download, return string
        contains relevant exception error string
        """

        #create error log variable
        status = ""
        ucsName = ""
        hostnameUrl = "https://"+self.F5IP+"/mgmt/tm/sys/global-settings"
        #set query string so it only return the hostname param in JSON
        hostnameParam = "$select=hostname"
        #fetch todays date
        currentDate = str(datetime.date.today())


        try:
            #send GET to retireve hostname of F5 device
            hostnameResp = requests.get(hostnameUrl, auth=(self.username,self.password), \
            params=hostnameParam, verify=False)
            hostnameResp.raise_for_status()
        except requests.exceptions.RequestException as e:
            #create exception text to use later in error report
            logging.debug(f"DEBUG exception {e}")
            status = f'ERROR generate_ucs GET call failed: {e}'
        else:
            #if hostname successfully retrieved, create UCS name
            ucsName = json.loads(hostnameResp.text)
            ucsName = ucsName["hostname"].split('.')[0]
            ucsName = ucsName+"_"+currentDate+"_" \
            +str(random.randint(100,300))+".ucs"

        #create JSON payload with comand to save ucs and name of ucs
        payload = {"command":"save", "name":ucsName}
        ucsUrl = "https://"+self.F5IP+"/mgmt/tm/sys/ucs/"

        #create UCS with creating an asynchronous task
        if not isLarge and not status:
            try:
                #send POST request to create UCS.
                startTime = time.perf_counter()
                resp = requests.post(ucsUrl, auth=(self.username,self.password), \
                json=payload, verify=False)
                resp.raise_for_status()
            except requests.exceptions.RequestException as e:
                logging.debug(f"DEBUG exception {e}")
                status = f'ERROR generate_ucs POST call failed: {e}'
                #set to true so API task will start. Assume timeout of previous POST
                #ie iControl limitation of 60 seconds
                isLarge = True
                stopTime = time.perf_counter()
            else:
                isLarge = False

        #if the UCS is quite large, or previous POST call (non-task) timedout
        #generate a UCS using an iControl task
        if isLarge and not status:
            ucsUrl = "https://"+self.F5IP+"/mgmt/tm/task/sys/ucs"
            #send request to create ucs task specifying ucs name in payload
            try:
                startTime = time.perf_counter()
                #create asynchronous task and locate '_taskId' in response,
                #remove any params
                createResp = requests.post(ucsUrl, auth=(self.username, self.password), \
                json=payload, verify=False)
                createResp.raise_for_status()
            except requests.exceptions.RequestException as e:
                status = f'ERROR generate_ucs TASK POST call failed: {e}'
                #any other errors, send email alert and abort
                logging.debug(f'DEBUG Starting task POST failed error: {e}')
            else:
                #200 success - create taskId for use later
                createJson = json.loads(createResp.text)
                taskId = "/"+str(createJson["_taskId"])
                logging.debug(f'DEBUG {taskId} and status {createResp.status_code}')

            if not status:
                ##start the asynchronous task with PUT request with selflink as endpoint
                ###specify 'VALIDATING' as '_taskstate' property
                startPayload = {"_taskState":"VALIDATING"}
                try:
                    startResp = requests.put(ucsUrl+taskId,auth=(self.username, self.password), \
                    json=startPayload, verify=False)
                    startResp.raise_for_status()
                except requests.exceptions.RequestException as e:
                    status = f'ERROR generate_ucs TASK PUT call failed: {e}'
                    #any other errors, send email alert and abort
                    logging.debug(f'DEBUG Starting task PUT failed error: {e}')
                else:
                    #received 202 response, verify 'task will exe asynchronously'
                    #message rx before querying for task status
                    startJson = json.loads(startResp.text)
                    taskExe = startJson["message"]
                    logging.debug(f'DEBUG PUT STATUS is {startResp.status_code}')
                    #verify task executing: in response look for "message" : "Task will execute
                    ##asynchronously"
                    if taskExe == "Task will execute asynchronously.":
                        #periodically send GET to monitor status of task, use while loop wait period
                        ##look for: "_taskState":"COMPLETED"
                        while True:
                            time.sleep(2)
                            try:
                                statusResp = requests.get(ucsUrl+taskId, \
                                auth=(self.username, self.password), verify=False)
                                statusResp.raise_for_status()
                            except requests.exceptions.RequestException as e:
                                status = f'ERROR generate_ucs TASK GET status call failed: {e}'
                                #any other errors, send email alert and abort
                                logging.debug(f'DEBUG GET task status failed error: {e}')
                            else:
                                #200 response - verify if "COMPLETED" status
                                statusJson = json.loads(statusResp.text)
                                logging.debug(f'DEBUG GET status STATUS{statusResp.status_code}')
                                if len(statusJson) != 0 and statusJson["_taskState"] == "COMPLETED":
                                    break
                if not status:
                    #when task completed,make GET to enpoint with /result
                    try:
                        resultResp = requests.get(ucsUrl+taskId+"/result", \
                        auth=(self.username, self.password), verify=False)
                        resultResp.raise_for_status()
                    except requests.exceptions.RequestException as e:
                        status = f'ERROR generate_ucs TASK GET result call failed: {e}'
                        #any other errors, send email alert and abort
                        logging.debug(f'DEBUG Some major error {e}')
                    else:
                        #response is 200, verify COMPLETED
                        resultJson = json.loads(resultResp.text)
                        logging.debug(f'DEBUG GET Result STATUS {resultResp.status_code}')
                        if len(resultJson) != 0 and resultJson["_taskState"] == "COMPLETED":
                            logging.debug(f'DEBUG GET /result status COMPLETED')
                            pass

                    if not status:
                        #Once we get a successful "COMPLETED" status from GET to /result, we
                        #should only need to send one DELETE to remove the result
                        try:
                            #send DELETE to remove result
                            delResultResp = requests.delete(ucsUrl+taskId+"/result", \
                            auth=(self.username, self.password), verify=False)
                            delResultResp.raise_for_status()
                        except requests.exceptions.HTTPError:
                            #if response is 400, then result has been deleted
                            delResultJson = json.loads(delResultResp.text)
                            if len(delResultJson) != 0 and delResultJson["code"] == 400:
                                logging.debug(f'DEBUG Result deleted')
                                pass
                        except requests.exceptions.RequestException as e:
                            status = f'ERROR generate_ucs TASK DELETE result call failed: {e}'
                            #any other errors, send email alert and abort
                            logging.debug(f'DEBUG Some major error {e}')
                        else:
                            #200 status and result deleted successfully
                            logging.debug(f'DEBUG Result deleted')
                            pass

                        if not status:
                            #once we have successully deleted the result, we should DELETE the task
                            try:
                                delTaskResp = requests.delete(ucsUrl+taskId, \
                                auth=(self.username, self.password), verify=False)
                                delTaskResp.raise_for_status()
                            except requests.exceptions.HTTPError:
                                #if task not found - then it has been deleted
                                delTaskJson = json.loads(delTaskResp.text)
                                if len(delTaskJson) != 0 and delTaskJson["message"].startswith("Task not found"):
                                    logging.debug(f'DEBUG Task Deleted')
                                    pass
                            except requests.exeptions.RequestException as e:
                                status = f'ERROR generate_ucs TASK DELETE task call failed: {e}'
                                #any other errors, send email alert and abort
                                logging.debug(f'DEBUG Some major error {e}')
                            else:
                                #must be 200 status and task deleted successfully
                                logging.debug(f'DEBUG Task deleted')
                                pass


        stopTime = time.perf_counter()
        if not status:
            status =  f'{ucsName} created in {stopTime - startTime:0.4f} seconds'

        #return the name of UCS file or return error code dictionary
        return status

    def download_ucs(self, ucsName, chunk_size=(512 * 1024)):
        """
        Downloads UCS to local directory

        Functionality:
        -The function will make an API call to GET a specified UCS file.
        file is buffered with specific chunk size.

        Attributes:
        The following instance attributes are used in API calls:
        -self.F5IP
        -self.username
        -self.password

        Parameters:
        ucsName - string, the name of the ucs file to verify
        chunk_size - integer, download chunk size, default=(512 * 1024)

        Exceptions:
        exceptions are caught for an requests module API calls and stored as
        a string to be returned for error logging

        Returns:
        A string indicating download status of UCS: if downloaded successfully,
        return string includes name, size and time to download. If unsuccessful
        download, return string contains relevant exception error string.

        Note:
        Most of this download content taken from here:
        https://devcentral.f5.com/s/articles/demystifying-icontrol-rest-part-5-transferring-files
        With URI path from here:
        https://f5-sdk.readthedocs.io/en/latest/userguide/file_transfers.html
        """

        #create error log variable
        status = ""
        fileSize = ""
        url = "https://"+self.F5IP+"/mgmt/shared/file-transfer/ucs-downloads/"
        headers = {
                'Content-Type': 'application/octet-stream'
            }
        #ucsDir = os.getcwd()+"\\F5Backups\\"
        with open(self.ucsDir+ucsName, 'wb') as f:
            start = 0
            end = chunk_size -1
            size = 0
            current_bytes = 0
            startTime = time.perf_counter()
            while True:
                content_range = f'{start}-{end}/{size}'
                headers['Content-Range'] = content_range
                logging.debug(f'DEBUG Content Range = {headers["Content-Range"]}')
                #stream=True tells requests that file will be buffered using
                #iter_content to control flow with specific chunk size
                try:
                    resp = requests.get(url+ucsName, headers=headers, \
                    auth=(self.username, self.password), verify=False, stream=True)
                    resp.raise_for_status()
                except requests.exceptions.RequestException as e:
                    #if API connection error, break and send status error message
                    logging.debug(f'ERROR download UCS GET issue {e}')
                    status = f'ERROR download_ucs GET failure {e}'
                    break
                else:
                    # If the size is zero, then this is the first time through the
                    # loop and we don't want to write data because we haven't yet
                    # figured out the total size of the file.
                    if size > 0:
                        current_bytes += chunk_size
                        for chunk in resp.iter_content(chunk_size):
                            f.write(chunk)

                    # Once we've downloaded the entire file, we can break out of
                    # the loop
                    if end == size:
                        break
                crange = resp.headers['Content-Range']
                fileSize = crange.split('/')[-1]
                # Determine the total number of bytes to read
                if size == 0:
                    #eg, Content-Range: bytes 200-1000/67589
                    size = int(crange.split('/')[-1]) - 1

                    # If the file is smaller than the chunk size, BIG-IP will
                    # return an HTTP 400. So adjust the chunk_size down to the
                    # total file size...
                    if chunk_size > size:
                        end = size

                    # ...and pass on the rest of the code
                    continue
                start += chunk_size

                if (current_bytes + chunk_size) > size:
                    end = size
                else:
                    end = start + chunk_size - 1

            stopTime = time.perf_counter()

        if not status:
            status = f'{ucsName}, size {fileSize}bytes, downloaded in {stopTime - startTime:0.4f} seconds UCSSUCCESS'

        return status

    def get_ucs_checksums(self, ucsName):
        """
        Calculates the md5 checksum of a UCS archive on the F5 and a local copy
        and checks for a match, thus ensuring data integrity

        Functionality:
        -The function will make an API call to get the checksum. This call
        is a POST to /mgmt/tm/util/bash/ to call the md5sum utility.
        -A checksum command is run against the local (previously downloaded)
        version of the UCS and the two checksum values compared for parity.

        Attributes:
        The following instance attributes are used in API calls:
        -self.F5IP
        -self.username
        -self.password

        Parameters:
        ucsName - string, the name of the ucs file to verify

        Exceptions:
        exceptions are caught for an requests module API calls and stored as
        a string to be returned for error logging

        Returns:
        string of the remote (on F5 box) and local (downloaded) checksums.
        If exception raised, exception string returned.

        Authentication:
        Requires admin account to run /bash commands
        """

        #create error log variable
        status = ""

        payload = {"command":"run", "utilCmdArgs":" -c 'md5sum /var/local/ucs/"+ucsName+"'"}
        #define the /util/bash path - need to be admin to run bash
        url = "https://"+self.F5IP+"/mgmt/tm/util/bash/"
        headers = {"Content-type" : "application/json"}
        remoteHash = ""
        #call API to get md5sum of on box ucs
        try:
            resp = requests.post(url, auth=(self.username, self.password),headers=headers, \
            json=payload, verify=False)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logging.debug(f'DEBUG POST md5sum call failed error: {e}')
            status = f'ERROR get_ucs_checksums POST call failed: {e}'
        else:
            respDict = json.loads(resp.text)
            remoteHash = respDict["commandResult"].split()[0]

        localHash = ""
        #if status empty (no exceptions to API call) and remoteHash contains a string
        if not status and remoteHash:
            #set current directory
            curPath = os.getcwd()
            #if local UCS exists, get checksum of local UCS copy
            if os.path.isfile(self.ucsDir+ucsName):
                with open(self.ucsDir+ucsName, 'rb') as f:
                    data = f.read()
                    localHash = hashlib.md5(data).hexdigest()
            else:
                status = "ERROR local file doesnt exist"

        #compare on-box and local copies of UCS, if they match return success string
        if remoteHash == localHash:
            logging.debug(f": {remoteHash}:{localHash}")
            status = f"Remotehash:Localhash {remoteHash}:{localHash}"

        return status


    def get_f5mk(self):
        """
        Retrieves the string value of the master key from the F5

        Functionality:
        -Makes an API call to the F5 to get the master key value. This call
        is a POST to /mgmt/tm/util/bash/ to call the f5mku utility.
        -The local file storing the masterkey is opened and the key resuting
        from the API call is compared to it. If the last line in the local file
        doesnt have a key match, the new masterkey is appended to the local file.

        Attributes:
        The following instance attributes are used in API calls:
        -self.F5IP
        -self.username
        -self.password

        Exceptions:
        exceptions are caught for an requests module API calls and stored as
        a string to be returned for error logging

        Returns:
        string indicating if masterkey was updated to local file or if masterkey
        is same as previous file entry. If exception raised, exception string
        returned.

        Authentication:
        Requires admin account to run /bash commands
        """

        #create error log variable
        status = ""

        timeNow = datetime.datetime.now()
        url = "https://"+self.F5IP+"/mgmt/tm/util/bash/"
        payload = {"command":"run", "utilCmdArgs":" -c 'f5mku -K'"}
        headers = {"Content-type" : "application/json"}
        masterKey = ""
        try:
            resp = requests.post(url, auth=(self.username, self.password),headers=headers, \
            json=payload, verify=False)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logging.debug(f'DEBUG POST to get f5mku: {e}')
            status = f'ERROR get_f5mk POST call failed: {e}'
        else:
            #get f5mk from JSON response and save as string
            masterKey = json.loads(resp.text)["commandResult"].split()[0]
        #bool to use in conditional to determine file write
        exists = False
        #open file in append+read mode, set current read postion to start of file
        #read in last line and compare to current masterkey returned b API call
        if not status and masterKey:
            with open("f5mk.txt", 'a+') as keyfile:
                keyfile.seek(0,0)
                lastline = (list(keyfile)[-1])
                if lastline.split("/")[-1] == masterKey:
                    #if masterkey already exists in file, do nothing
                    exists = True
                    status = f'f5mk same as previous on: {lastline.split("/")[0]}'
                #if current key different than masterkeys in file, append current to file
                if not exists:
                    keyfile.write(f'\n{timeNow}/{masterKey}')
                    status = f'new f5mk appended'

        return status

    def cleanup_ucs(self, deleteOlder):
        """
        Delete UCS archives older than 'deleteOlder' from the F5

        Functionality:
        -Makes an API call to get a list of UCS' and parse
        them into a dictionary with keywords as UCS hostnames and the
        values as lists containing the UCS filesize and creation date
        -Then loops through the dictionary of UCS files and sends
        an API call to DELETE any older than argument 'deleteOlder' days

        Attributes:
        The following instance attributes are used in API calls:
        -self.F5IP
        -self.username
        -self.password

        Parameters:
        deleteOlder - integer, determines age in days for which UCS archives
        older than will be deleted

        Exceptions:
        exceptions are caught for an requests module API calls and stored as
        a string to be returned for error logging

        Returns:
        A string indicating status of deletion of old UCS files: if deleted UCS,
        its name and creation date; if no UCS' old enough to be deleted,
        timestamp returned. If exception raised, exception string retruned.
        """

        url = "https://"+self.F5IP+"/mgmt/tm/sys/ucs"
        #create dictionary to store on box ucs name,size,age
        ucsDict = {}
        #create error log variable
        status = ""
        try:
            resp = requests.get(url, auth=(self.username,self.password), verify=False)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            #any other errors, send email alert and abort
            logging.debug(f'DEBUG GET ucs list failed error: {e}')
            status = f'ERROR cleanup_ucs GET call failed: {e}'
        else:
            #from resp, create dict with filename:list of size and creation date
            for k,v in json.loads(resp.text).items():
                if k == 'items':
                    for value in v:
                        dict1 = value
                        for key, value in dict1.items():
                            if key == 'apiRawValues':
                                ucsList = []
                                ucsList.append(value["file_created_date"])
                                ucsList.append(value['file_size'])
                                ucsDict[value["filename"]] = ucsList
        logging.debug(f'DEBUG {ucsDict} status = {status}')
        #if no exceptions so far and ucsDict is not empty, evaluate for deletion
        if status == "" and ucsDict:
            #get UTZ/Zulu time now - datetime.datetime function below will be UTC
            now = datetime.datetime.utcnow()
            #delta = age in days after which ucs' will be deleted
            delta = datetime.timedelta(days=deleteOlder)
            #set bool to use to determine if anything deleted
            deletedUcs = False
            for k,v in ucsDict.items():
                #setup datetime object for relative date comparison
                ucsYear, ucsMonth, ucsDay, ucsHour, ucsMin = v[0][0:4], v[0][5:7], \
                v[0][8:10], v[0][11:13], v[0][14:16]
                ageUcs = datetime.datetime(int(ucsYear), int(ucsMonth), \
                int(ucsDay), int(ucsHour), int(ucsMin))
                if (ageUcs+delta) < now:
                    #split the name of the ucs from its path and store in ucsDel
                    ucsDel = "/"+k.split('/')[-1]
                    try:
                        delResp = requests.delete(url+ucsDel, auth=(self.username,self.password), \
                        verify=False)
                        delResp.raise_for_status()
                    except requests.exceptions.RequestException as e:
                        logging.debug(f'DEBUG DELETE ucs failed error: {e}')
                        status = f'ERROR cleanup_ucs DELETE call failed: {e}'
                    else:
                        deletedUcs = True
                        status = status+f'DELETED: {ucsDel} created on {ageUcs}; '
            #meaningful message if no exception raised nor UCS successfully deleted
            if not status:
                        status = f'Nothing to Delete {now}'
        return status
