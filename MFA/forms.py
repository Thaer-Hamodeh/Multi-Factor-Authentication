from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from MFA.models import User

# here we should add some validators for User
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)],
                           render_kw={"placeholder": "User Name"})
    email = StringField('Email', validators=[DataRequired(), Email()],
                        render_kw={"placeholder": "Email"})
    phone = StringField('Phone Number', validators=[Length(min=10,max=10),DataRequired()],
                        render_kw={"placeholder": "Phone Number in this form : 0611111111"})
    password = PasswordField('Password', validators=[DataRequired()],
                             render_kw={"placeholder": "Password"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')],
                                     render_kw={"placeholder": "Confirm Password"})
    authentication=SelectField('Authentication Type', choices=[('QR','QR Authentication'),('Face','Face Recognition'),
                                                               ('SMS','SMS Authentication')])
    recaptcha = RecaptchaField()
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

    def validate_phone(self, phone):
        user = User.query.filter_by(phone=phone.data).first()
        if user:
            raise ValidationError('That phone is already used. Please choose a different phone number.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"placeholder": "E-mail"})
    password = PasswordField('Password', validators=[DataRequired()],render_kw={"placeholder": "Password"})
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RequestVerifyEmail(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"placeholder": "E-mail"})
    submit = SubmitField('Send Email')

class ResetPassword(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()],render_kw={"placeholder": "New Password"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={"placeholder": "Confirm New Password"})
    submit = SubmitField('Reset Password')

class QRForm(FlaskForm):
    qr_code = StringField('QR', validators=[DataRequired(), Length(min=6, max=6)], render_kw={"placeholder": "Enter Passcode"})
    submit = SubmitField('Confirm Code')

class SMSForm(FlaskForm):
    sms_code = StringField('SMS', validators=[DataRequired(), Length(min=6, max=6)], render_kw={"placeholder": "Enter Passcode"})
    submit = SubmitField('Confirm Code')

class TakePhoto(FlaskForm):
    submit = SubmitField('Submit')
