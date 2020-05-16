
#! python3
#git at cloudsecurity period nz

import smtplib, datetime
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
"""
A very small Class to send emails with specified sender, recipient, subject, body and
attachments.

This is tested to send SMTP messages to an on-prem Exchange server after
editing receive connector to allow py script server IP 
"""
class SendEmail:

    def __init__(self, smtpServer='10.9.8.7', sender='donald@whitehouse.gov'):
        """initialise instance"""
        self.smtpserver = smtpServer
        self.sender = sender


    def sendEmail(self, subject, body, *recipients, **attachments):
        #create MIMEMultipart object to store mesage details
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = self.sender
        #msg['To'] needs to be a string of recipients
        msg['To'] = ", ".join(recipients)
        #add test to body of email
        msg.attach(MIMEText(body, 'plain'))
        if attachments:
            msg.preamble = 'Please see attached file'
            for file in attachments.values():
                #open attachment in binary read mode, read as MIMEImage binary, attach to msg
                attach = open(file, 'rb')
                img = MIMEImage(attach.read())
                #name of attachment is key from **attachments
                img.add_header('Content-Disposition', 'attachment', filename=file)
                attach.close()
                msg.attach(img)

        #create SMTP object
        mail = smtplib.SMTP(self.smtpserver, 25)
        #turn on debug so can see all responses
        mail.set_debuglevel(1)
        #send SMTP hello
        mail.ehlo()
        #send mail - dont need to mail.login() as no password required - whitelisted IP
        #msg.as_string() collects together all MIME elements including attachment
        #multiple recipients for 'mail.sendmail()' need to be a list
        mail.sendmail(self.sender, list(recipients), msg.as_string())
        mail.quit()
