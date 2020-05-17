git @ cloudsecurity period nz

--------------
PYTHON SCRIPTS
--------------

This repository contains the following python scripts/projects:

-f5_backups
Sample scripts, calling the F5Archive class, to create and download a UCS archive,
verify download integrity with checksum and delete UCS' older than X days.
The F5Archive class also has a method to download the F5 masterkey, which is useful if you have a standalone F5 unit.


-f5_vpn_snamp_stats
Sample scripts to periodically pull SNMP data (VPN users, memory, cpu) from
specified F5 units and store data in a text file.
This should be run as a cron job/scheduled task at desired interval, ie every 15 mins.
This was written for F5 units running BIGIP version 11.6.5. It is a tactical solution
for pulling data from older F5 units (the API stats for VPN usage were inaccurate.)
Uses pysnmp package for SNMP polling.

-paloalto_minemeld_backups
Script to create and download backups from Palo Alto Minemeld Servers 
and store in specified local directory
I have this set as a cron job for clients.

-paloalto_panorama_backups_tags
Short scripts to:
- call Palo Alto Panorama XML API and get running config file
- store file in local backup directory
- parse running-config file to find security rules with specific tags
to be used as reminder for auditing etc
This is configured to send SMTP messages to an on-prem Exchange server after
editing receive connector to allow py script server IP 

