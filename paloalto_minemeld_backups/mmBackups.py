#! python3.8
#git at cloudsecurity period nz


import json, requests, os, time, random, logging
from datetime import date
"""
Script to create and download backups from Palo Alto Minemeld Servers 
and store in specified local directory

I have this set as a cron job for clients.
"""


logging.basicConfig(level=logging.DEBUG, format="{asctime} {processName:<12} \
{message} ({filename}:{lineno})", style="{")
logging.disable(logging.CRITICAL)


def mmBackup(IP, username, password):
    """
    Creates a mimemeld backup file and downloads and writes to local directory

    Functionality:
    -Makes an API call to start backup job
    -iterates API calls to determine status of backup job
    -If status is 'DONE', makes API call to download file and store in specified
    directory

    Parameters:
    The following instance attributes are used in API calls:
    -IP - the IP of the minemeld server
    -username - minemeld admin account username
    -password - minemeld admin account password

    Exceptions:
    exceptions are caught for an requests module API calls and stored as
    a string (status) to be returned for error logging

    Returns:
    succesful minemeld backup returns string with name of file; unsuccessful
    results in exception error string
    """
    #set site ID based on IP
    if IP == '10.2.3.4':
        siteA = 'SiteA'
    if IP == '10.5.6.7':
        siteB = 'SiteB'
    #set time, date and random variables for use in backup filenames
    epoch = "?_="+str(int(time.time()))
    today = date.today()
    day = today.strftime("%d_%m_%Y")
    randy = str(random.randint(100,900))+"_"
    #set API URLs
    exportUrl = "https://"+IP+"/status/backup"
    statusUrl = "https://"+IP+"/jobs/status-backup/"

    #set directory location to store the backup files
    backupFile = os.getcwd()+"\\MMBackups\\"+randy+day+"_"+site+"minemeld.zip"
    #set required header values
    exportHeader = {"Content-Type" : "application/json"}
    downloadHeader = {"Content-Type" : "application/zip"}
    #set variables: status for return string; jobString to store backup job string
    #provided by minemeld; ready boolean to determine when backup file ready to download
    status, jobString = "", ""
    ready = False
    #make API call to minemeld to request backup job started
    try:
        exportResp = requests.post(exportUrl+epoch, auth=(username,password), \
        json={"p":"backup_password"}, verify=False, headers = exportHeader)
        exportResp.raise_for_status()
    except requests.exceptions.RequestException as e:
        #any other errors, send email alert and abort
        logging.debug(f'DEBUG POST export backup failed error: {e}')
        status = f'ERROR POST export backup call failed: {e}'
    else:
        #if successful API call, store jobstring as string to use later
        jobString = json.loads(exportResp.text)['result']
        if jobString:
            #enter loop, waiting 2 seconds each iteration, to query API for
            #status on backup job usinf jobString value
            while not ready:
                try:
                    time.sleep(2)
                    statusResp = requests.get(statusUrl+jobString, auth=(username, password), verify=False)
                    statusResp.raise_for_status()
                except requests.exceptions.RequestException as e:
                    #any other errors, send email alert and abort
                    logging.debug(f'DEBUG GET export status failed error: {e}')
                    status = f'ERROR GET export status call failed: {e}'
                else:
                    statusString = json.loads(statusResp.text)['result']['status']
                    #if response json body 'status' key is 'Done,' exit loop
                    if statusString == 'DONE':
                        ready = True
            try:
                #once status DONE confirmed, download the backup file
                downloadResp = requests.get(exportUrl+"/"+jobString, auth=(username, password), verify = False, headers = downloadHeader)
                downloadResp.raise_for_status()
            except requests.exceptions.RequestException as e:
                #any other errors, send email alert and abort
                logging.debug(f'DEBUG GET export download failed error: {e}')
                status = f'ERROR GET export download call failed: {e}'
            else:
                #write backup file to specified directory
                with open(backupFile, 'wb') as file:
                    file.write(downloadResp.content)
                if os.path.exists(backupFile) and os.path.getsize(backupFile) > 1000:
                    status = os.path.basename(backupFile)+" Filesize "+str(os.path.getsize(backupFile)/1000)+"KB\n\n"
    #return name of file, if backup successful; else, return exception details
    return status

#call the function
siteABackup = mmBackup("10.2.3.4", 'admin', "password")
siteBBackup = mmBackup("10.5.6.7", 'admin', "password")

