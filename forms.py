from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=30)])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')



class KeyExchangeForm(FlaskForm):
    client_public_key = StringField('Your Public Key', validators=[DataRequired()])
    submit = SubmitField('Exchange Keys')



class OTPGenerationForm(FlaskForm):
    otp_secret = StringField('OTP Secret', validators=[DataRequired()])
    submit = SubmitField('Generate OTP')
