# DiscordInboxify
This is a public version of a simple GUI tool I made to greatly improve the speed at which tickets can be created in CRM from Discord messages from clients. 
DiscordInboxify is a simple and efficient tool that allows you to convert Discord tickets into emails, making it easier for you to manage your support requests. 

## Features
- Converts Discord messages into emails
- Simple and efficient tool for decreasing time it takes to create a ticket from Discord messages/requests
- Checks if credentials are in the right format
- Checks for empty input
- Uses SMTP to send email, very easy to expand functionality in MailSender class
- Informs on successful/unsuccessful email send
- Stores credentials locally in the working directory as a hidden encrypted file
- Has hints on hover

## Requirements
- Python3 
- Discord account
- CRM software compatible with email integration
- This version requires a Gmail account to be used as email sender, but any will work with a simple tweak
- Following libraries:
    smtplib,
    email.mime.text,
    re,
    os,
    base64,
    cryptography,
    sys,
    PyQt5.

## Getting Started
Clone the repository: git clone https://github.com/lordicode/DiscordInboxify.git

Navigate to the project directory.

Install dependencies.

Run the sendmail.py.

## Screenshots
- First screen. Generate and input the app password to be used for sending emails to the CRM-linked email account. 
This screen will not appear again as the credentials are locally saved and then retrieved.
![image](https://i.ibb.co/2kHCbwZ/python-e7a79-OZSHs.png)
- Second screen. Copy the Discord ID of the user, then the content of their message. Press submit.  
![image](https://i.ibb.co/bF1FJ9T/python-g-IOx-Q6z-ENK.png)

## License
DiscordInboxify is licensed under the MIT license.