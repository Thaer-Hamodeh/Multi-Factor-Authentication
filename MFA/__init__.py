import os, sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_socketio import SocketIO

app = Flask(__name__)
# Check the OS in order to get the OS variables
if sys.platform == "win32":
    app.config['MAIL_USERNAME'] = os.environ.get('Unit_UN')
    app.config['MAIL_PASSWORD'] = os.environ.get('Unit_PW')
    app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get('Public_Rec')
    app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ.get('Private_Rec')
    app.config['SECRET_KEY'] = os.environ.get('APP_Secret')
    account_sid = os.environ.get('sms_id')
    auth_token = os.environ.get('sms_key')
    map_token = os.environ.get('map_token')
else:
    print("other OS")
    print(sys.platform)

# Configuring DB and Mail server
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_ASCII_ATTACHMENTS ']=True

db = SQLAlchemy(app)
# Encrypting the app
bcrypt = Bcrypt(app)

# Login configuration
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.refresh_view='relogin'
login_manager.needs_refresh_message='Session timeout, please re-login'
login_manager.login_message_category = 'info'

mail = Mail(app)
socketio=SocketIO(app)

# Google maps API
end_point = "https://maps.googleapis.com/maps/api/staticmap?"

from MFA import routes