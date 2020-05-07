from MFA import db, login_manager, app, account_sid, auth_token, end_point, mail, map_token
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from otpauth import OtpAuth
import qrcode, random, base64, cv2, io, geocoder, os, face_recognition, requests
import numpy as np
from flask_mail import Message
from PIL import Image
from twilio.rest import Client
from datetime import datetime
from flask_socketio import emit


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initializing the table User in the DB with internal functions
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(10), nullable=False)
    activated = db.Column(db.Boolean, nullable=False, default=0)
    face_confirmed = db.Column(db.Boolean, nullable=False, default=0)
    qr_confirmed = db.Column(db.Boolean, nullable=False, default=0)
    sms_confirmed = db.Column(db.Boolean, nullable=False, default=0)
    auth_mode = db.Column(db.String(60), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    authenticated = db.Column(db.Boolean, nullable=False, default=0)
    sms_code = db.Column(db.String(6))
    valid_ip = db.Column(db.String(255))
    check_time = db.Column(db.String(20), nullable=False,default='0')
    time_out = db.Column(db.Boolean, nullable=False, default=0)
    oneTime_reg = db.Column(db.Boolean, nullable=False, default=0)

    # Creating the token in order to be added in the sent emails
    def create_token(self, validity):
        if validity is None:
            s = Serializer(app.config['SECRET_KEY'])
        else:
            s = Serializer(app.config['SECRET_KEY'], expires_in=validity)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    # Verifying the received token
    @staticmethod
    def verify_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return False
        return User.query.get(user_id)

    # create QR code that contains user ID
    def create_qr(self):
        id = str(self.id)
        auth = OtpAuth(app.config['SECRET_KEY'] + id)  # a secret string
        email = self.email
        s = auth.to_uri('totp', email, 'Unit963')
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=15,
            border=5,
        )
        qr.add_data(s)
        img = qr.make_image(fill_color="#05528a", back_color="white")
        img.save('./MFA/static/QR/' + id + '.png')

    # Send security email in case of logging in from different location
    def send_security_email(self, ip, device, browser, ver):
        token=self.create_token(None)
        g = geocoder.ip(ip)
        userInfo = g.geojson
        print(userInfo)
        address = userInfo['features'][0]['properties']['address']
        city1 = userInfo['features'][0]['properties']['city']
        lat = userInfo['features'][0]['properties']['lat']
        lng = userInfo['features'][0]['properties']['lng']
        zoom = 14
        maptype = "hybrid"
        mapReq = end_point + "center=" + city1 + "&zoom=" + str(zoom) + "&markers=" + str(lat)+"," + str(lng) +\
                 "&size=400x400&maptype=" + maptype + "&key=" + map_token
        r = requests.get(mapReq)
        with open("./MFA/static/maps/"+str(self.id)+"_map.png", "wb") as f:
            f.write(r.content)
            f.close()
        receiver_email = self.email
        now = datetime.now()
        time = now.strftime("%d/%m/%Y %H:%M:%S")
        msg = Message('Security Alert',
                      sender='unit963.hva@gmail.com',
                      recipients=[self.email])
        msg.html='''<body>
            <b><h1>Security Alert</h1></b>
            <hr> 
            <p>Hey, did you try to login? A login attempt has been made.</br>
            <ul>
            <li>When: <b>{time}</b></li></br>
            <li>Device: <b>{device} - Ver: {ver}</b></li></br>
            <li>Browser: <b>{browser}</b></li></br>
            <li>Near: <b>{address}</b></li></br>
            <li>IP: <b>{ip}</b></li></ul><br>
            If that is you, then you can click <a href="http://80.112.190.136:80/save_ip/{token}/{ip}">here</a> to save this location.<br>
            If you suspect that someone else is trying to get into your account please contact our tech center.<br> 
            </p>
        </body>
        '''.format(ip = ip, token=token, address=address, email=receiver_email, device=device, browser=browser,
                   ver=ver, time=time)
        # change ip to proper one : 80.112....
        with app.open_resource("static/maps/"+str(self.id)+"_map.png") as fp:
            msg.attach("static/maps/"+str(self.id)+"_map.png", "image/png", fp.read())
        mail.send(msg)

    # Send confirmation email after registration
    def send_confirmation_email(self):
        token = self.create_token(120)
        msg = Message('Email address confirmation',
                      sender='unit963.hva@gmail.com',
                      recipients=[self.email])
        msg.body = f'''To confirm your E-mail click on the following link:
    http://127.0.0.1:5000/confirm_email/{token}
    If you did not make this request then simply ignore this email and no changes will be made.
    '''
        mail.send(msg)

    def send_unblock_account(self):
        token = self.create_token(None)
        msg = Message('Suspicious login activity warning',
                      sender='unit963.hva@gmail.com',
                      recipients=[self.email])
        msg.body = f'''Your account has been blocked for suspicious activity. To unblock your E-mail click on the following link:
    http://127.0.0.1:5000/unblock_user/{token}
    '''
        mail.send(msg)

    # Send email to reset password
    def send_reset_password(self):
        token = self.create_token(120)
        msg = Message('Reset Password Link',
                      sender='unit963.hva@gmail.com',
                      recipients=[self.email])
        msg.body = f'''To reset your password click on the following link:
    http://127.0.0.1:5000/confirm_email/{token}
    If you did not make this request then simply ignore this email and no changes will be made.
    '''
        mail.send(msg)

    # Verify the QR code after logging in
    def verify_qr(self):
        id= str(self.id)
        auth = OtpAuth(app.config['SECRET_KEY'] + id)  # a secret string
        return auth.totp()

    # Send sms with code in order to login
    def send_sms(self):
        client = Client(account_sid, auth_token)
        numberList = []
        for i in range(6):
            randomNumber = random.randint(0, 9)
            numberList.append(str(randomNumber))
        code = "".join(numberList)
        userTelNumDB = self.phone
        phone = userTelNumDB[1 : : ]
        message = client.messages.create(body="Your Code is:\n" + str(code),
                                            from_='+15103191855',
                                            to='+31'+ phone)
        print(message.sid)
        self.sms_code = code
        db.session.commit()

    # Create user photo
    def create_photo(self, id, img):
        with open("./MFA/static/profile_pics/"+str(id) + ".jpg", "wb") as f:
            f.write(base64.b64decode(img))
            print("done from models")
    
    # When user confirm his face ID, success or failed photo will be shown
    def send_logo(self, logo):
        with open("./MFA/static/images/" + logo + ".png", "rb") as imageFile:
            image_byte = base64.b64encode(imageFile.read())
            stringData = image_byte.decode("utf-8")
            b64_src = 'data:image/jpg;base64,'
            stringData = b64_src + stringData
            emit('response_back', stringData)
    
    # Check the face if it matches the user's face photo
    def image_processing(self, img):
        id= str(self.id)
        print(id)
        imgdata = base64.b64decode(img)
        image = Image.open(io.BytesIO(imgdata))
        imgRGP = cv2.cvtColor(np.array(image), cv2.COLOR_BGR2RGB)
     
        known_image = face_recognition.load_image_file("./MFA/static/profile_pics/"+id +".jpg")
        known_face_encodings = face_recognition.face_encodings(known_image)

        # Find all the faces and face encodings in the current frame of video
        face_locations = face_recognition.face_locations(imgRGP)
        face_encodings = face_recognition.face_encodings(imgRGP, face_locations)

        for face_encoding in face_encodings:
           # See if the face is a match for the known face(s)
            matches = face_recognition.compare_faces(known_face_encodings, face_encoding)

            # If a match was found in known_face_encodings, just use the first one.
            if True in matches:
                return True
            elif False in matches:
                return False

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.phone}')"
