
#! python3
#git at cloudsecurity period nz


import datetime, pysnmp, datetime, logging
from pysnmp.hlapi import *
logging.basicConfig(level=logging.DEBUG, format="{asctime} {processName:<12} \
{message} ({filename}:{lineno})", style="{")
#logging.disable(logging.CRITICAL)

"""
A sample script to periodically pull SNMP data (VPN users, memory, cpu) from
specified F5 units and store data in a text file.

This should be run as a cron job/scheduled task at desired interval, ie every 15 mins.

This was written for F5 units running BIGIP version 11.6.5. It is a tactical solution
for pulling data from older F5 units (the API stats for VPN usgae were inaccurate.)

Uses pysnmp package for SNMP polling.
"""

#establish time/date variables
getDate = datetime.datetime.now()
time = str(getDate.strftime("%d/%m/%Y %H:%M:%S"))+" "
date = str(getDate.strftime("_%d_%m_%Y"))

f5DestAkl = '10.11.12.13'
f5DestWlg = '10.12.13.14'
f5DestWlg002 = '10.13.14.15'
#the second half of the OID is object specific, ie the specific leasepool
oidMyvpnUsersAkl = '.1.3.6.1.4.1.3375.2.6.2.1.3.1.3.<specific object part of oid>'
oidMyvpnUsersWlg = '.1.3.6.1.4.1.3375.2.6.2.1.3.1.3.<specific object part of oid>'
#the .0 on end is essential if no child instances of oid, ie total memory used
oidCpu = '.1.3.6.1.4.1.3375.2.1.1.2.20.37.0'
oidMemTotal = '.1.3.6.1.4.1.3375.2.1.1.2.1.143.0'
oidMemUsed ='.1.3.6.1.4.1.3375.2.1.1.2.1.144.0'

def getSnmpResponse(f5Dest, oid):
    """polls the specified F5 devices for SNMP values for specified OIDs.

    Parameters:
    -f5Dest - String specifying IP of F5 unit to be polled
    -oid - String specifying the F5 MIB OID value sought

    Returns:
    String of OID value
    """
    status = ""
    #call getcmd to get snmp response
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData('public'),
               UdpTransportTarget((f5Dest, 161)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)), lookupMIB=False)
    )
    #if errorindication or errorstatus returned by getcmd:
    if errorIndication:
        status = f'ERROR {errorIndication}'
    elif errorStatus:
        status = f'ERROR {errorStatus.prettyprint()}, {errorIndex}'
    else:
    #else pull value from snmp response and return with timestamp in list
        for varBind in varBinds:
        # varBind is a object with 'mib=value', create list with = separator
            snmpResponse = str(varBind).split('=')
            logging.debug(f'Varbind = {varBind}')
            #returned OID response value from list response
            returnedValues = snmpResponse[1]
    if status:
        return status
    else:
        return returnedValues

#pull memory values from both AkL/Wlg and convert to int to calculate usage %
memTotalValueWlg = int(getSnmpResponse(f5DestWlg, oidMemTotal))
memUsedValueWlg = int(getSnmpResponse(f5DestWlg, oidMemUsed))
memTotalValueAkl = int(getSnmpResponse(f5DestAkl, oidMemTotal))
memUsedValueAkl = int(getSnmpResponse(f5DestAkl, oidMemUsed))
#calculate usage % by rounding memtotal/100 to 2 digits and then
#using it to divide memUsed to find %, then round to whole number
memUsedPercentWlg = str(round((memUsedValueWlg /round((memTotalValueWlg /100), 2))))
memUsedPercentAkl = str(round((memUsedValueAkl /round((memTotalValueAkl /100), 2))))
#pull CPU OID and round it to whole number
cpuPercentWlg = str(round(int(getSnmpResponse(f5DestWlg, oidCpu))))
cpuPercentAkl = str(round(int(getSnmpResponse(f5DestAkl, oidCpu))))
#pull Current APM users
apmCurrentUsersWlg = str(int(getSnmpResponse(f5DestWlg, oidMyvpnUsersWlg)))
apmCurrentUsersAkl = str(int(getSnmpResponse(f5DestAkl, oidMyvpnUsersAkl)))

#open file to save to same values oid file each day
with open(f'valuesWlg{date}.txt', 'a') as valuesFileWlg, \
open(f'valuesAkl{date}.txt', 'a') as valuesFileAkl:
#write values to file
    valuesFileWlg.write(f'\n'+time+" "+memUsedPercentWlg+" "+cpuPercentWlg+" "\
    +apmCurrentUsersWlg)
    valuesFileAkl.write(f'\n'+time+" "+memUsedPercentAkl+" "+cpuPercentAkl+" "\
    +apmCurrentUsersAkl)
