#! python3
#git at cloudsecurity period nz
from f5Archive import F5Archive as F5A
import logging
"""
This is a sample script to create and download a UCS archive,
verify download integrity with checksum and delete UCS' older than X days.
All using the F5Archive class.

Returns:
String with concatenated status of each method call
Could extend script by sending status string as email update or log to file.
"""


#Instantiate F5Archive
archive = F5A("10.9.8.7", 'admin', 'somepassword')
ucs = ""
downloadNewUcs = ""
status = ""
newUcs = archive.generate_ucs()
#if UCS created successfully, get ucs name and add to status string
if newUcs.endswith('seconds'):
    status = newUcs
    ucs = newUcs.split()[0]
    downloadNewUcs = archive.download_ucs(ucs)
    #if UCS downloaded successfully, get details and add to status string
    if downloadNewUcs.endswith("UCSSUCCESS"):
        status = status+" "+downloadNewUcs
        checksum = archive.get_ucs_checksums(ucs)
        #if checksums successfully match, get details and add to status string
        if checksum.startswith("Remote"):
            status = status+" "+checksum
            deleteUcs = archive.cleanup_ucs(7)
            #if old UCS' successfully deleted, get details and add to status string
            if deleteUcs.startswith('DELETED'):
                status = status+" "+deleteUcs
            #else print status and exception string
            else:
                status = status+" "+deleteUcs
        #else print status and exception string
        else:
            status = status+" "+checksum
    #else print status and exception string
    else:
        status = status+" "+downloadNewUcs
#else print exception string
else:
    status = newUcs

#do something with status string
print(status)
