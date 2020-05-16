#! python3
#git at cloudsecurity period nz
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import datetime, shutil, os, logging, random, re
import numpy as np

logging.basicConfig(level=logging.DEBUG, format="{asctime} {processName:<12} \
{message} ({filename}:{lineno})", style="{")
#logging.disable(logging.CRITICAL)

class CreateImage:
    """
    This class formats snmp stats retrieved using program getF5Snmp.py
    into lists used by matplotlib to create a graph showing VPN usage of the
    specified F5. The resulting graph is stored in local directory.

    Methods:
    This program has the following functions:
    -getFormattedData - opens the snmp stats files created by getF5Snmp.py,
    parses the contents into lists of: time, cpu, memory, user stats for
    use within class instance. This method calculates the time point with
    highest number of vpn users and corresponding memory and cpu usage and
    populates self.max with the data as a string.
    -get_image - takes the lists of snmp stats created by getFormattedData and
    uses them in matplotlib to create a usage graph showing:
            -- x axis = time
            -- left y axis = number of VPN users
            -- right y axis =  cpu and memory %
    The description of under the x axis is the self.max data calculated in
    getFormattedData() method.
    Returns string of the name of the graph file created

    Instance Attributes:
    The following attributes are instatiated for use by the class methods:
    -self.site - string name of the site with the F5 device being polled
    -self.date - string date of the data you want to graph
    -self.max  - string variable to store max user/mem/cpu values
    -self.time - list to store timestamps for every snmp poll
    -self.mem - list to store periodic polled memory data
    -self.cpu - list to store periodic polled cpu data
    -self.users - list to store periodic polled vpn user data
    -self.lst - list for temporary use in parsing snmp data from files
    """

    def __init__(self, site, date):
        #initialise instance and attributes
        self.site, self.date, self.max  = site, date, ""
        self.time, self.mem, self.cpu, self.users, self.lst = [], [], [], [], []


    def getFormattedData(self):
        """
        formats data from files with raw snmp data into (instance attribute)
        lists usable by matplotlib in getImage() method:
        -self.time - list to store timestamps for every snmp poll
        -self.mem - list to store periodic polled memory data
        -self.cpu - list to store periodic polled cpu data
        -self.users - list to store periodic polled vpn user data
        Parses lists to find highest VPN user stats for that date and save as string
        """
        #create date string separated by '_' not '/' so that it will save in windows OS
        dateU = re.sub('/', '_', self.date)
        #define the name of the file to pull data from
        logging.debug("DEBUG"+dateU)
        dataFile = 'values'+self.site+'_'+dateU+".txt"
        TEMPdataFile = 'TEMP'+dataFile
        #copy that file in cwd so we are not working with live file
        shutil.copy('C:\\Users\\user\\Documents\\py\\Users\\new\\'+dataFile, \
        'C:\\Users\\user\\Documents\\py\\Users\\new\\'+TEMPdataFile)

        #open the working copy of the data file and read contents
        with open(TEMPdataFile, 'r') as file:
            #read in the contents of the the file
            #split out time, mem, cpu and users into individual lists of integers
            contents = file.readlines()
            for line in contents:
                lst = line.split()
                #if not empty line --> snmp script creates empty line first
                if lst:
                    self.time.append(lst[1])
                    self.mem.append(int(lst[2]))
                    self.cpu.append(int(lst[3]))
                    self.users.append(int(lst[4]))

            #create loop to find daily max users and index from users list
            maxUsers, maxIndex = 0, 0
            for index in range(len(self.users)):
                if self.users[index] > maxUsers:
                    maxUsers, maxIndex = self.users[index], index
            #find respective time, mem, cpu using index position of max users
            maxTime, maxMem = str(self.time[maxIndex]), str(self.mem[maxIndex])
            maxCpu, maxUsers = str(self.cpu[maxIndex]), str(maxUsers)

            #create string with date, max users/cpu/mem to return
            self.max = self.date+" (Most Users: "+maxTime+", "+maxUsers+\
            " VPN Users, CPU "+maxCpu+"%, Memory "+maxMem+"%)"

        #delete working file
        os.unlink('C:\\Users\\user\\Documents\\py\\Users\\new\\'+TEMPdataFile)


    def getImage(self):
        """
        Creates vpn usage graph in local directory using data from lists
        generated in getFormattedData() method.
        -self.time - list to store timestamps for every snmp poll
        -self.mem - list to store periodic polled memory data
        -self.cpu - list to store periodic polled cpu data
        -self.users - list to store periodic polled vpn user data

        Returns string of name of image.
        """
        #format the snmp data by calling peer (see above) method getFormattedData()
        self.getFormattedData()

        #convert to numpy array, apparently less issues with matplotlib
        self.mem = np.array(self.mem)
        self.cpu = np.array(self.cpu)
        self.users = np.array(self.users)

        #create a figure and one subplot - necessary for every graph
        fig, ax1 = plt.subplots()

        #set x and y axis (left side) values
        color = 'tab:red'
        ax1.set_title(self.site+' F5 VPN Users and Resources')
        ax1.set_xlabel(self.max)
        ax1.set_ylabel('VPN Users', color=color)
        ax1.set_xlim(auto=True)
        ax1.set_ylim(0,300)
        #plot the values out in line
        ax1.plot(self.time, self.users, color=color, label='VPN Users', linewidth=3)
        #set the color of the numbering up the first y axis
        ax1.tick_params(axis='y', labelcolor=color)
        ax1.autoscale(enable=True, axis='x')
        #set x axis tick values (ie time) to be 60degrees
        plt.setp(ax1.get_xticklabels(), rotation=60, ha="right")

        ax2 = ax1.twinx()  # instantiate the other y axis that shares the same x-axis

        #set second y axis (right side) values
        color = 'tab:blue'
        ax2.set_ylabel('CPU %, Mem %', color=color)# we already handled x-label with ax1
        ax2.set_ylim(0, 100) #set limit to 100; no set_ylim means axis auto-scales up
        #plot the second and third lines (cpu/mem)
        ax2.plot( self.time, self.cpu, color=color, marker="o", label='CPU %')
        ax2.plot( self.time, self.mem, color=color, linestyle = 'dashed', label='Memory %')
        #set the color of the numbering up the second y axis
        ax2.tick_params(axis='y', labelcolor=color)

        #set legend to distinguish lines in graph
        ax1.legend(loc='upper left', frameon=False)
        ax2.legend(loc='upper right', frameon=False)

        fig.tight_layout()  # otherwise the right y-label is slightly clipped
        figure = plt.gcf() # get current figure
        #set size of canvas
        figure.set_size_inches(18, 6)
        #Output to user
        #plt.show()

        #save to file
        # when saving, specify the DPI
        randy = str(random.randint(300, 900))
        #create date string separated by '_' not '/' so that it will save in windows OS
        dateU = re.sub('/', '_', self.date)
        #create name of image and save image to local directory
        imageName = randy+"_"+self.site+dateU+".png"
        plt.savefig(imageName, dpi = 100)

        #return the image name
        return imageName
