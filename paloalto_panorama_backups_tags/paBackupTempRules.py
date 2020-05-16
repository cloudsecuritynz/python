#! python3
#git at cloudsecurity period nz
from sendEmail import SendEmail as email
import requests, os, shutils, random
import xml.etree.ElementTree as ET
from datetime import date
"""
A short script to:
- call Palo Alto Panorama XML API and get running config file
- store file in local backup directory
- parse running-config file to find security rules with specific tags
to be used as reminder for auditing etc

This is configured to send SMTP messages to an on-prem Exchange server after
editing receive connector to allow py script server IP 
"""

today = date.today()

#create date string and random int string for use in the name of the file download
day = today.strftime("%d_%m_%Y")
randy = str(random.randint(100,900))+"_"
#prepare API call and authentication header
apiKey = {"X-PAN-KEY" : "LUFRPridiculouslylongapistringOaQ=="}
url = "https://10.34.35.36/api/?type=export&category=configuration"


#determine the full path for the config backup file to go to
backupFile = os.getcwd()+"\\PABackups\\"+randy+day+"_running-config.xml"
resp = requests.get(url, headers=apiKey, verify=False)
status = ""
try:
    #download file and write to specified backup location
    with open(backupFile, 'wb') as file:
        file.write(resp.content)
except IOError as e:
    #if exception, send error string indicating API call failed
    status = f"ERROR downloading Panorama backup file {e}"
    logging.debug(f"DEBUG file write error: {e}")
else:
    #open and parse the downloaded XML config file
    tree = ET.parse(backupFile)
    root = tree.getroot()
    auditRules, deviceGroups = [], []
    desc = ""
    #determine the number of data groups
    for dgs in root.findall("./devices/entry/device-group/"):
        deviceGroups.append(dgs.attrib['name'])

    #for each DG, search every security rule for a 'audit' tag and append
    #the data group, name and description of each rule found as en entry in list
    #auditRules, concatenate each entry in the list into a string separated by ==
    for dc in deviceGroups:
        for rules in root.findall("./devices/entry/device-group/*[@name='"+dc+"']/pre-rulebase/security/rules/entry"):
            desc = rules.find('description').text
            ruleName = rules.attrib['name']
            for tags in rules.getchildren():
                if tags.tag == "tag":
                    for tagNames in tags.getchildren():
                        if tagNames.text == "audit":
                            auditRules.append(dc+"=="+ruleName+"=="+desc)

if status == "":
    ruleCount = 1
    bodyString = ""
    dgRules = {}
    for deviceGroup in deviceGroups:
        dgRules[deviceGroup] = ""

    for rule in auditRules:
        ruleDg = rule.split("==")[0]
        ruleName = rule.split("==")[1]
        ruleDesc = rule.split("==")[2]
        if dgRules[ruleDg] != "":
            dgRules[ruleDg] = dgRules[ruleDg]+"\n"+str(ruleCount)+")  Rule Name: "+ruleName+"\t(Description: "+ruleDesc+")"
            ruleCount += 1
        else:
            dgRules[ruleDg] = "\n\nDevice-Group "+ruleDg+" 'audit' tagged rules:\n"+str(ruleCount)+")  Rule Name: "+ruleName+"\t(Description: "+ruleDesc+")"
            ruleCount += 1
    for v in dgRules.values():
        bodyString = bodyString+v
    backupName = "\nPanorama Backup Successfully Created: "+os.path.basename(backupFile)+" Filesize "+str(os.path.getsize(backupFile)/1000)+"KB\n\n"
    body = backupName+bodyString
    subject = "Palo Alto Configuration- "+str(len(auditRules))+" Security rules with 'audit' tag"
else:
    body = status
    subject = "Palo Alto backup failed"

new = email()
new.sendEmail(subject, body, "email1@e.com", "email2@e.com","email3@e.com")
