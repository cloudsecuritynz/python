#! python3
#git at cloudsecurity period nz

import smtplib, datetime, re
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from createImage import CreateImage as ci

"""
A sample script to instantiate the CreateImage Class to create an image showing
a graph of VPN usage statistics for the defined date.
The created image is then emailed to specified recipients.
Email connectivity is via on-prem exchange with IP of python script server 
configured in receive connector to send emails via SMTP
"""

x = datetime.datetime.now()
currentDate = x.strftime("%d/%m/%Y")

#instantiate CreateImage objects for each F5
newImageWlg = ci("Wlg", currentDate)
newImageAkl = ci("Akl", currentDate)

#call method getImage() to return name of image file
imageWlg = newImageWlg.getImage()
imageAkl = newImageAkl.getImage()

COMMASPACE = ', '
rbnz_smtp = '10.11.12.14'
myEmail = 'electric@boogaloo.com'
recipientEmail = 'mechanical@boogaloo.com'
subject = f"Today's F5 VPN Usage Stats\n"
emailBody = f'{subject}Attached are the images showing F5 usage stats'
file = 'usersGraph.png'

#create MIMEMultipart object to store mesage details
msg = MIMEMultipart()
msg['Subject'] = subject
msg['From'] = myEmail
msg['To'] = recipientEmail
msg.preamble = 'Please see attached file'

#open attachment in binary read mode, read as MIMEImage binary, attach to msg
fpw = open(imageWlg, 'rb')
img = MIMEImage(fpw.read())
#add_header adds name to attachment, otherwise listed as 'noname'
img.add_header('Content-Disposition', 'attachment', filename=imageWlg)
fpw.close()
msg.attach(img)
fpa = open(imageAkl, 'rb')
img = MIMEImage(fpa.read())
#add_header adds name to attachment, otherwise listed as 'noname'
img.add_header('Content-Disposition', 'attachment', filename=imageAkl)
fpa.close()
msg.attach(img)



#create SMTP object
mail = smtplib.SMTP(rbnz_smtp, 25)
#turn on debug so can see all responses
mail.set_debuglevel(1)
#send SMTP hello
mail.ehlo()
#send mail - dont need to mail.login() as no password required - whitelisted IP
#msg.as_string() collects together all MIME elements including attachment
mail.sendmail(myEmail, recipientEmail, msg.as_string())
mail.quit()
