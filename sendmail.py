# adds functionality to send emails through Simple Mail Transfer Protocol server
import smtplib
# to allow for creation of plain text email messages
from email.mime.text import MIMEText
# pattern matching
import re
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QHBoxLayout, QVBoxLayout, \
    QWidget, QMessageBox, QTextEdit, QPlainTextEdit, QDesktopWidget
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt


class MailSender:
    def __init__(self, in_username, in_password, in_server=("smtp.gmail.com", 587), use_ssl=False):
        self.username = in_username
        self.password = in_password
        self.server_name, self.server_port = in_server
        self.use_SSL = use_ssl
        self.connected = False
        self.recipients = []
        self.msg = None

        if self.use_SSL:
            self.smtpserver = smtplib.SMTP_SSL(self.server_name, self.server_port)
        else:
            self.smtpserver = smtplib.SMTP(self.server_name, self.server_port)
        self.connected = False
        self.recipients = []

    def __str__(self):
        return "Type: Mail Sender \n" \
               "Connection to server {}, port {} \n" \
               "Connected: {} \n" \
               "Username: {}, Password: {}".format(self.server_name, self.server_port, self.connected, self.username,
                                                   self.password)

    def set_message(self, in_plaintext, in_subject="", in_from=None, in_htmltext=None):

        if in_htmltext is not None:
            self.html_ready = True
        else:
            self.html_ready = False

        if self.html_ready:
            self.msg.attach(MIMEText(in_plaintext, 'plain'))
        else:
            self.msg = MIMEText(in_plaintext, 'plain')

        self.msg['Subject'] = in_subject
        if in_from is None:
            self.msg['From'] = self.username
        else:
            self.msg['From'] = in_from
        self.msg["To"] = None
        self.msg["CC"] = None
        self.msg["BCC"] = None

    def set_recipients(self, in_recipients):

        if not isinstance(in_recipients, (list, tuple)):
            raise TypeError("Recipients must be a list or tuple, is {}".format(type(in_recipients)))

        self.recipients = in_recipients

    def connect(self):

        if not self.use_SSL:
            self.smtpserver.starttls()
        self.smtpserver.login(self.username, self.password)
        self.connected = True
        print("Connected to {}".format(self.server_name))

    def disconnect(self):
        self.smtpserver.close()
        self.connected = False

    def send_all(self, close_connection=True):

        if not self.connected:
            raise ConnectionError("Not connected to any server. Try self.connect() first")

        print("Message: {}".format(self.msg.get_payload()))

        for recipient in self.recipients:
            self.msg.replace_header("To", recipient)
            print("Sending to {}".format(recipient))
            self.smtpserver.send_message(self.msg)

        print("Email sent. Ticket will be created automatically.")

        if close_connection:
            self.disconnect()
            print("Connection closed")
            return True


def send_email(app_password_send, email_account_sender_send, client_discord_id, client_message):
    try:
        smtp_server = "smtp.gmail.com"
        port = 587

        # this is used in our CRM to properly categorize tickets and assign to the right bucket,
        # please change it to what you need
        common_word = "DISCORD"
        # which CRM-connected email account should the ticket/email be sent to
        support_account_receiver = "yourcrmemail@legitcorporatedomain.com"

        message_discord_requester = common_word + " " + client_discord_id
        message_body_plaintext = client_message

        with smtplib.SMTP(smtp_server, port):
            our_mail_sender = MailSender(email_account_sender_send, app_password_send, (smtp_server, port))

            our_mail_sender.set_message(message_body_plaintext, message_discord_requester)

            our_mail_sender.set_recipients([support_account_receiver])

            our_mail_sender.connect()
            if our_mail_sender.send_all():
                return True
            else:
                return False
    except Exception as e:
        print(e)
        return False


def encrypt_values(value1, value2):
    # takes password and salt to encrypt the app password and email to be stored locally
    password = b"youveryhardpassword"
    salt = b"yoursupersaltysalt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    fernet = Fernet(key)

    # Encrypt the values
    encrypted_value1 = fernet.encrypt(value1.encode())
    encrypted_value2 = fernet.encrypt(value2.encode())

    # Save the encrypted values to a file
    with open("encrypted_values.bin", "wb") as file:
        file.write(encrypted_value1 + encrypted_value2)
        # change the file's attributes to hidden using the os module
        os.system('attrib +H "{}"'.format(file.name))


def decrypt_values():
    # Load the encrypted values from the file
    with open("encrypted_values.bin", "rb") as f:
        encrypted_values = f.read()
    # must be identical to encrypt_values()!
    password = b"youveryhardpassword"
    salt = b"yoursupersaltysalt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    fernet = Fernet(key)

    # Decrypt the values
    decrypted_value1 = fernet.decrypt(encrypted_values[:len(encrypted_values) // 2]).decode()
    decrypted_value2 = fernet.decrypt(encrypted_values[len(encrypted_values) // 2:]).decode()

    return decrypted_value1, decrypted_value2


class InitialWindow(QMainWindow):
    # ticket window parsed as global value to be able to launch the ticket window from this one
    def __init__(self, ticket_window):
        super().__init__()
        self.setWindowTitle("Input password and email")
        self.setGeometry(100, 100, 500, 400)
        self.init_ui()
        self.ticket_window = ticket_window

    def submit(self):
        # match any valid Gmail account address
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@gmail\.com$')
        # match the format of the Gmail app password
        app_password_pattern = re.compile(r'^[a-z0-9]+$')
        # retrieve the entered text from the app password input window
        app_password_get = self.password_input.text()
        print(f"Type of app_password: {type(self.password_input)}")
        if not app_password_get:
            print("No value entered in the app password input widget")
        else:
            print(app_password_get)
        # retrieve the entered text from the email input window
        email_account_sender_get = self.email_input.text()
        print(f"Type of email_account_sender: {type(self.email_input)}")
        if not email_account_sender_get:
            print("No value entered in the email input widget")
        else:
            print(email_account_sender_get)

        # check if the values are valid by pattern matching, if not return until they are matching
        if not email_pattern.match(email_account_sender_get) and app_password_pattern.match(app_password_get):
            QMessageBox.warning(self, "Warning", "Invalid Gmail address")
            return
        elif not app_password_pattern.match(app_password_get) and email_pattern.match(email_account_sender_get):
            print(app_password_get, app_password_pattern)
            QMessageBox.warning(self, "Warning", "App password should contain only lowercase alphanumeric characters")
            return
        elif not email_pattern.match(email_account_sender_get) and not app_password_pattern.match(app_password_get):
            QMessageBox.warning(self, "Warning", "Email is not a valid Gmail account. App password is not valid Gmail "
                                                 "app password")
            return
        # encrypt the values and store them in a hidden file. Done just for the sake of it :)
        encrypt_values(app_password_get, email_account_sender_get)
        # close the initial window and open the ticket window passing the
        try:
            self.close()
            ticket_window.show()
        except Exception as e:
            print("Error opening TicketWindow:", e)

    def init_ui(self):
        self.setWindowIcon(QIcon('main_and_first.ico'))
        self.setStyleSheet("background-image: url(bg.png); color: white; font: bold 22px;")

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        password_hbox = QHBoxLayout()
        password_label = QLabel('App Password', self)
        self.password_input = QLineEdit(self)
        password_hint = QLabel('<a href="">?</a>', self)
        password_hint.setContentsMargins(5, 5, 5, 5)
        password_hint.setAlignment(Qt.AlignCenter)
        password_hint.setToolTip('Please generate Gmail app password and input it here')
        password_hint.setStyleSheet("QToolTip { color: #ffffff; background-color: #000000; border: 1px solid white; }")
        password_hbox.addWidget(password_label)
        password_hbox.addWidget(self.password_input)
        password_hbox.addWidget(password_hint)

        email_hbox = QHBoxLayout()
        email_label = QLabel('Email', self)
        self.email_input = QLineEdit(self)
        email_hint = QLabel('<a href="">?</a>', self)
        email_hint.setAlignment(Qt.AlignCenter)
        email_hint.setContentsMargins(5, 5, 5, 5)
        email_hint.setToolTip('Your work Gmail account address')
        email_hint.setStyleSheet("QToolTip { color: #ffffff; background-color: #000000; border: 1px solid white; }")
        email_hbox.addWidget(email_label)
        email_hbox.addWidget(self.email_input)
        email_hbox.addWidget(email_hint)

        submit_button = QPushButton('Submit', self)
        submit_button.clicked.connect(self.submit)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(10, 10, 20, 5)
        vbox.setSpacing(0)
        vbox.addLayout(password_hbox)
        password_hbox.setSpacing(0)
        password_hbox.setContentsMargins(10, 10, 10, 10)
        vbox.addLayout(email_hbox)
        email_hbox.setSpacing(0)
        email_hbox.setContentsMargins(10, 10, 10, 10)
        vbox.addWidget(submit_button)

        central_widget.setLayout(vbox)


class TicketWindow(QMainWindow):
    def __init__(self, app_password_ticket_window, email_account_sender_ticket_window):
        super().__init__()

        self.setWindowTitle("Discord Ticket Creation")
        self.setGeometry(100, 100, 500, 400)
        self.setWindowIcon(QIcon('second_screen.ico'))
        self.setStyleSheet("background-image: url(bg.png); color: white; font: bold 20px;")
        self.app_password = app_password_ticket_window
        self.email_account_sender = email_account_sender_ticket_window

        self.client_discord_id = QLineEdit()
        # QTextPlainEdit is multiline, which may be required for Discord messages. additionally it parses only plain
        # getting rid of unnecessary elements
        self.client_message = QPlainTextEdit()
        self.client_discord_id.setFixedHeight(28)
        self.client_message.setMinimumSize(500, 150)
        desktop = QDesktopWidget()
        self.client_message.setMaximumSize(desktop.availableGeometry().width(), 660)
        self.client_message.lineWrapMode()
        label_discord_id = QLabel("Client Discord ID:")
        label_message = QLabel("Client Message:")
        submit_button = QPushButton("Submit")

        clear_credentials_button = QPushButton("Clear credentials")
        try:
            submit_button.clicked.connect(self.submit)
        except Exception as e:
            print(e)

        layout = QVBoxLayout()
        layout.addWidget(label_discord_id)
        layout.addWidget(self.client_discord_id)
        layout.addWidget(label_message)
        layout.addWidget(self.client_message)
        layout.addWidget(submit_button)
        layout.addWidget(clear_credentials_button)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def submit(self):
        # all discord ids have # in them, this just checks if the full discord ID has been copied
        pattern_discord_id = re.compile(r'.*#.*')
        client_discord_id = self.client_discord_id.text()
        client_message = self.client_message.toPlainText()
        self.client_message.setPlainText("")
        self.client_discord_id.clear()
        if client_message and pattern_discord_id.match(client_discord_id):
            if send_email(self.app_password, self.email_account_sender, client_discord_id, client_message):
                QMessageBox.information(self, "Success",
                                        "Email sent successfully. Ticket will be created automatically")
            else:
                # email of someone in charge of keeping this in working order
                QMessageBox.warning(self, "Warning",
                                    "Something went wrong, if you cannot figure out what happened, please contact:\n"
                                    "klavdii.chopats@oxygen-forensic.com")
        else:
            QMessageBox.warning(self, "Warning",
                                "Something went wrong, either Discord ID is incorrect or message is empty")

    def clear_credentials(self):
        if os.path.exists("encrypted_values.bin"):
            os.remove("encrypted_values.bin")
            QMessageBox.information(self, "Information", "Credentials have been cleared.")
            self.close()
        else:
            QMessageBox.warning(self, "Warning", "No credentials found.")

# launches the window if the script is run directly
if __name__ == '__main__':
    # creates an instance of QApplication, empty list because there is no command line arguments
    app = QApplication([])
    # if there is a hidden file in the directory and there is some values in it, then it means that his application ran
    # already and app password and email have been provided. Just need to decrypt and retrieve them.
    if os.path.exists("encrypted_values.bin") and os.path.getsize("encrypted_values.bin") > 0:
        app_password, email_account_sender = decrypt_values()
        # pass the decrypted values to the window
        window = TicketWindow(app_password, email_account_sender)
        window.show()
        sys.exit(app.exec_())
    else:
        app_password, email_account_sender = None, None
        ticket_window = TicketWindow(app_password, email_account_sender)
        window = InitialWindow(ticket_window)
        window.show()
        sys.exit(app.exec_())
