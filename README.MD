# PYTHON SCRIPTS


## This repository contains the following python scripts/projects:

- **f5_backups:**
  - Scripts *(**NOT** using the F5 Python SDK)* to:
    - create and download a UCS archive
    - verify download integrity with checksums
    - delete UCS' older than X days
    - download the F5 masterkey, which is useful if you have a standalone F5 unit.


- **f5_vpn_snmp_stats:**
  - Scripts to periodically pull SNMP data (VPN users, memory, cpu) from
    specified F5 units and store data in a text file.
  - This should be run as a cron job/scheduled task at desired interval, ie every 15 mins.
  - This was written for F5 units running BIGIP version 11.6.5. It is a tactical solution
    for pulling data from older F5 units (the API stats for VPN usage were inaccurate.)
  - Uses pysnmp package for SNMP polling and matplotlib for graph image creation
![vpnusers](/images/vpnusers.png)


- **f5_daily_device_checks:**
  - Scripts to periodically (daily) retrieve device stats using API and format into a string
    usable (plain text) in the body of an email.
  - Clients requested this to run daily at start of Business Hours to serve as additional Operation checks process.
  - NOTE: this is not a replacement for realtime device monitoring, ie utilising a SOC, but as an additional 
    operational check as part of a belt-and-braces monitoring strategy
  - This was written for F5 units running BIGIP version v13x-14.x. Should work in v11.
  - Uses requests package for calling iControl API
  - Example output below
![vpnusers](/images/f5_daily_checks.PNG)


- **f5_ssl_certs_expiry:**
  - Scripts to periodically query F5 device looking for traffic (SSL/TLS) certs dure to expire within specified, eg 2 months, timeframe.
  - Note: F5 v11.x.x 'check-certs' utility doesnt work, hence netmiko used.
  - Tested against: v11.6.5, v14.1.2.3, v14.1.2.6
  - Example output below
![vpnusers](/images/vpnusers.png)


- **paloalto_minemeld_backups:**
  - Script to create and download backups from Palo Alto Minemeld Servers 
    and store in specified local directory


- **paloalto_panorama_backups_tags:**
  - Short script to:
    - call Palo Alto Panorama XML API and get running config file
    - store file in local backup directory
    - parse running-config file to find security rules with specific tags
      to be used as reminder for auditing etc
    - create a basic email listing security rules with specified tag and basic backup file details
![email](/images/emailtags.png)  


- **paloalto_daily_device_checks:**
  - Scripts to periodically (daily) retrieve device stats using XML API and format into a string
    usable (plain text) in the body of an email.
  - Clients requested this to run daily at start of Business Hours to serve as additional Operation checks process.
  - NOTE: this is not a replacement for realtime device monitoring, ie utilising a SOC, but as an additional 
    operational check as part of a belt-and-braces monitoring strategy
  - This was written for PA/Panorma units running v9.x. A brief look tells me it should work for v8.x
  - Uses requests package for calling XML API and xmltodict to parse
  - Example output below
![vpnusers](/images/paloalto_daily_checks.PNG)

