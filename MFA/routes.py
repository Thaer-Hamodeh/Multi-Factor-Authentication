from flask import render_template, url_for, flash, redirect, abort, session, request
from MFA import app, db, bcrypt, socketio
from MFA.forms import RegistrationForm, LoginForm, RequestVerifyEmail, ResetPassword, QRForm, TakePhoto, SMSForm
from MFA.models import User
from datetime import timedelta
from flask_login import login_user, current_user, logout_user, login_required
from flask_socketio import emit
import time

# Configuring the session valid time 10 minutes
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=10)


# Sending email_function
def send_email(user):
    try:
        user.send_confirmation_email()
        flash('Email has been sent to verify your account! Verify it to be able to log in', 'success')
    except:
        flash(
            'Email sending failed.. Click on verify Email below to get email again', 'info')

# Home page after logging_in
@app.route("/")
@app.route("/home")
@login_required
def home():
    if current_user.authenticated:
        return render_template('home.html', title='Home Page')
    else:
        return redirect(url_for('login'))


# Registration page
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.authenticated:
            return redirect(url_for('home'))
        else:
            return redirect(url_for('login'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, phone=form.phone.data, password=hashed_password,
                    auth_mode=form.authentication.data, valid_ip=request.remote_addr+" ")
        db.session.add(user)
        db.session.commit()
        # Register with QR factor
        if user.auth_mode == 'QR':
            user.create_qr()
            session['dump_qr'] = user.id
            send_email(user)
            return redirect(url_for('qr'))
        # Register with SMS factor
        elif user.auth_mode == 'SMS':
            send_email(user)
            return redirect(url_for('login'))
        # Register with face factor
        else:
            session['dump_face'] = user.id
            send_email(user)
            return redirect(url_for('take_photo'))

    return render_template('register.html', title='Register', form=form)

# Login logic
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated and current_user.authenticated:
        return redirect(url_for('home'))
    else:
        form = LoginForm()
        logout_user()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                if request.remote_addr in user.valid_ip:
                    if user.activated:
                        login_user(user, remember=form.remember.data)
                        user.authenticated = False
                        if user.auth_mode == "QR":
                            user.qr_confirmed = False
                            db.session.commit()
                            session['counter'] = 0
                            return redirect(url_for('qr_confirm'))
                        elif user.auth_mode == "Face":
                            user.time_out = False
                            user.check_time = "0"
                            user.face_confirmed = False
                            user.oneTime_reg = False
                            db.session.commit()
                            return redirect(url_for('face_confirm'))
                        elif user.auth_mode == "SMS":
                            user.sms_confirmed = False
                            user.send_sms()
                            session['counter'] = 0
                            return redirect(url_for('sms'))
                    else:
                        flash(
                            'Activate your E-mail first to be able to login', 'danger')
                else:
                    device = request.user_agent.platform
                    browser = request.user_agent.browser
                    ver = request.user_agent.version
                    user.send_security_email(
                        request.remote_addr, device, browser, ver)
            else:
                flash('Login Unsuccessful. Please check email and password', 'danger')
        return render_template('login.html', title='Login', form=form)

# Adding new IP address to the safe IP list
@app.route("/save_ip/<token>/<ip>", methods=['GET', 'POST'])
def save_ip(token, ip):
    user = User.verify_token(token)
    if ip in user.valid_ip:
        pass
    else:
        user.valid_ip += (ip + " ")
        db.session.commit()
    flash("Your IP address has been saved", "success")
    return render_template('add_ip.html', ip=ip, title='Success - Redirecting')


# SMS confirmation page
@app.route("/sms", methods=['GET', 'POST'])
@login_required
def sms():
    form = SMSForm()
    if current_user.auth_mode != "SMS":
        return redirect(url_for('login'))

    if form.validate_on_submit():
        val = session['counter']
        if val == 1:
            current_user.activated = False
            db.session.commit()
            current_user.send_unblock_account()
            session.clear()
            logout()
        val = val + 1
        session['counter'] = val
        enteredKey = form.sms_code.data
        if enteredKey == current_user.sms_code:
            current_user.sms_confirmed = True
            current_user.authenticated = True
            db.session.commit()
            return redirect(url_for('home'))
        else:
            flash('SMS code is incorrect', 'danger')
    return render_template("sms_conf.html", title="SMS Verification", form=form)


# Logging_out the user
@app.route("/logout")
@login_required
def logout():
    if current_user.is_authenticated or current_user.authenticated:
        if current_user.auth_mode == "QR":
            current_user.qr_confirmed = False
        elif current_user.auth_mode == "Face":
            current_user.check_time = "0"
            current_user.authenticated = False
            current_user.face_confirmed = False
        elif current_user.auth_mode == "SMS":
            current_user.sms_confirmed = False
        session.clear()
        current_user.authenticated = False
        db.session.commit()
        logout_user()
    return redirect(url_for('login'))


# Confirming email address
@app.route("/confirm_email/<token>", methods=['GET', 'POST'])
def confirm_email(token):
    user = User.verify_token(token)
    try:
        if not user:
            abort(404)
        elif user.activated:
            flash('Your email is already confirmed', 'info')
            return redirect(url_for('login'))
        else:
            user.activated= True
            db.session.commit()
            flash('Email Confirmed.. now you can login', 'success')
    except AttributeError:
        abort(404)
    return render_template('blank.html')

# Unblock user account
@app.route("/unblock_user/<token>", methods=['GET', 'POST'])
def unblock_user(token):
    user = User.verify_token(token)
    try:
        if not user:
            abort(404)
        elif user.activated:
            return redirect(url_for('login'))
        else:
            user.activated= True
            db.session.commit()
            flash('User account has been activated.. now you can login', 'success')
    except AttributeError:
        abort(404)
    return render_template('blank.html')


# In case of activation link expired, the user will request a new confirmation
@app.route("/request_verify_email", methods=['GET', 'POST'])
def request_verify_email():
    form = RequestVerifyEmail()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.activated:
                flash('Your Email is already verified.', 'success')
                return redirect(url_for('login'))
            else:
                user.send_confirmation_email(120)
                flash('Confirmation Email has been sent.', 'success')
                return redirect(url_for('login'))
        else:
            flash('Email not found', 'danger')
            return redirect(url_for('register'))
    return render_template('request_verify_email.html', title='Verify Email address', form=form)


# Reset password request
@app.route("/request_reset_password", methods=['GET', 'POST'])
def request_reset_password():
    form = RequestVerifyEmail()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            user.send_reset_password(120)
            flash('Email with reset link has been sent', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found', 'danger')
            return redirect(url_for('register'))
    return render_template('request_reset_password.html', title='Request Reset Password', form=form)


# Reset password confirm
@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    form = ResetPassword()
    user = User.verify_token(token)
    try:
        if not user:
            abort(404)
        else:
            if form.validate_on_submit():
                hashed_password = bcrypt.generate_password_hash(
                    form.password.data).decode('utf-8')
                user.password = hashed_password
                db.session.commit()
                flash('Password has been reset', 'success')
                return redirect(url_for('login'))
    except AttributeError:
        abort(404)
    return render_template('reset_password.html', title='Reset Password', form=form)

# QR code for user with QR factor
@app.route("/qr", methods=['GET', 'POST'])
def qr():
    try:
        if session['dump_qr']:
            return render_template('qr.html', title='QR code', id=session['dump_qr'])
    except:
        if current_user.is_authenticated:
            if current_user.authenticated:
                if current_user.auth_mode == 'QR':
                    return render_template('qr.html', title='QR code', id=current_user.id)
                else:
                    return redirect(url_for('home'))
            else:
                return redirect(url_for('login'))
        else:
            return redirect(url_for('login'))


# Confirming the QR code
@app.route("/qr_confirm", methods=['GET', 'POST'])
@login_required
def qr_confirm():
    if current_user.auth_mode != "QR":
        return redirect(url_for('login'))
    user = User.query.filter_by(id=current_user.id).first()
    if user.authenticated:
        return redirect(url_for('home'))
    form = QRForm()
    user = User.query.filter_by(id=current_user.id).first()
    dump = str(user.verify_qr())
    if form.validate_on_submit():
        val = session['counter']
        if val == 1:
            current_user.activated=False
            db.session.commit()
            current_user.send_unblock_account()
            session.clear()
            logout()
        val=val+1
        session['counter']=val
        if form.qr_code.data == dump:
            user.qr_confirmed = True
            user.authenticated = True
            db.session.commit()
            return redirect(url_for('home'))
        else:
            flash('Incorrect passcode Try Again', 'danger')
    return render_template('qr_confirm.html', title='QR Confirm', form=form)


# Add new face to the user
@app.route("/take_photo", methods=['POST', 'GET'])
def take_photo():
    form = TakePhoto()
    try:
        if session['dump_face']:
            if form.validate_on_submit():
                return redirect(url_for('login'))
            return render_template('take_photo.html', title='Take Photo', form=form)
    except:
        if current_user.is_authenticated and current_user.authenticated:
            if current_user.auth_mode == 'Face':
                if form.validate_on_submit():
                    return redirect(url_for('home'))
                return render_template('take_photo.html', title='Take Photo', form=form)
            else:
                return redirect(url_for('home'))
        else:
            return redirect(url_for('login'))

# Processing adding the new face
@app.route("/save_photo", methods=['POST', 'GET'])
def save_photos():
    img = request.form.get("content").split(',')[1]
    try:
        if session['dump_face']:
            user = User.query.filter_by(id=session['dump_face']).first()
            user.create_photo(id=user.id, img=img)
    except:
        if current_user.is_authenticated and current_user.authenticated:
            if current_user.auth_mode == 'Face':
                current_user.create_photo(id=current_user.id, img=img)
    return "got it"


# Face confirm page
@app.route("/face_confirm", methods=['POST', 'GET'])
def face_confirm():
    try:
        if current_user.auth_mode != "Face":
            return redirect(url_for('login'))
        else:
            if current_user.time_out:
                flash('Login again! \nPage timeout!', 'danger')
                current_user.time_out = False
                db.session.commit()
                logout_user()
                return redirect(url_for('login'))
            elif current_user.face_confirmed:
                current_user.is_authenticated = True
                db.session.commit()
                return redirect(url_for('home'))
            return render_template('face_confirm.html', title='Face Recognition')
    except:
        return redirect(url_for('login'))


# Process confirming the face while logging_in
@socketio.on('image', namespace='/processing')
@login_required
def handle_my_custom_namespace_event(image):
    if current_user.is_authenticated:
        millisec = int(round(time.time() * 1000))
        user = User.query.filter_by(id=current_user.id).first()
        face_check = user.image_processing(img=str(image).split(',')[1])

        if face_check:
            user.face_confirmed = True
            user.authenticated = True
            db.session.commit()
            user.send_logo("success")
            time.sleep(1)
            if not user.oneTime_reg:
                print("send")
                emit('response', "find")
                current_user.oneTime_reg = True
                db.session.commit()
        elif face_check == False:
            user.send_logo("failed")
            user.face_confirmed = False
            db.session.commit()

        # start timer
        if user.check_time == "0":
            user.check_time = str(millisec)
            db.session.commit()
        # # 120000 milliseconds means 2 min
        elif int(current_user.check_time) + 12000 < millisec:
            print('timeOut')
            user.time_out = True
            db.session.commit()
            emit('response', "refresh")
            logout()


