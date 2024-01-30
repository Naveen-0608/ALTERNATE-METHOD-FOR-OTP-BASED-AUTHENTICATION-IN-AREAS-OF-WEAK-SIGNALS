from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from models import db,User, GeneratedKey
import random
import hashlib
import os
import pyotp
import qrcode
import base64
import io
from io import BytesIO
import string
import datetime
from pyotp import TOTP

app = Flask(__name__)
app.secret_key = '1306'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///navee.sqlite3'
db = SQLAlchemy(app)
db.init_app(app)
auth = None

with app.app_context():
    db.create_all()

def generate_unique_identifier():
    length = 6  # You can adjust the length of the identifier as needed
    characters = string.ascii_letters + string.digits
    identifier = ''.join(random.choice(characters) for _ in range(length))
    return identifier

def generate_6_digit_key():
    return ''.join(random.choice('0123456789') for _ in range(6))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    address = db.Column(db.String(200))
    password = db.Column(db.String(120), nullable=False)
    login_count = db.Column(db.Integer, default=0)
class GeneratedKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    generated_key = db.Column(db.String(6), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    age = StringField('Age')
    gender = StringField('Gender', validators=[DataRequired()])
    address = StringField('Address')
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
class OTPGenerationForm(FlaskForm):
    otp_secret = StringField('Your PIN to access', validators=[DataRequired()])
    submit = SubmitField('Generate OTP')
class DiffieHellmanAuth:
    def __init__(self):
        self.prime = 23
        self.generator = 5

        self.private_key_client, self.public_key_client = self.diffie_hellman()
        self.private_key_server, self.public_key_server = self.diffie_hellman()

        self.shared_secret_client = self.calculate_shared_secret(self.public_key_server, self.private_key_client)
        self.shared_secret_bytes = self.shared_secret_client.to_bytes((self.shared_secret_client.bit_length() + 7) // 8, byteorder='big')
        self.hmac_key = hashlib.sha256(self.shared_secret_bytes).digest()



    def diffie_hellman(self):
        private_key = random.randint(1, self.prime - 1)
        public_key = pow(self.generator, private_key, self.prime)
        return private_key, public_key

    def calculate_shared_secret(self, public_key, private_key):
        return pow(public_key, private_key, self.prime)

    def generate_otp(self, otp_secret):
        # Create an OTP based on the shared secret and provided OTP secret
        totp = TOTP(otp_secret)
        generated_otp = totp.now()
        return generated_otp

    def verify_otp(self, otp_input):
        # Verify the OTP provided by the user
        totp = TOTP(self.hmac_key, interval=30)
        return totp.verify(otp_input)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'error')
        else:
            user = User(
                username=form.username.data,
                phone_number=form.phone_number.data,
                email=form.email.data,
                age= form.age.data,
                gender=form.gender.data,
                address=form.address.data,
                password=form.password.data
            )
            db.session.add(user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))  # Redirect to login page
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    global auth
    if auth is None:
        auth = DiffieHellmanAuth()  # Initialize DiffieHellmanAuth instance

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            session['logged_in'] = True
            session['username'] = username
            user.login_count += 1  # Increment the login count
            db.session.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('generate_qr'))  # Redirect to QR code generation page
        else:
            flash('Login failed. Invalid credentials.', 'error')

    return render_template('login.html')

@app.route('/generate_otp', methods=['GET', 'POST'])
def generate_otp():
    global auth
    if auth is None:
        auth = DiffieHellmanAuth()  # Initialize DiffieHellmanAuth instance

    user = User.query.filter_by(username=session['username']).first()

    form = OTPGenerationForm()
    if form.validate_on_submit():
        # Generate OTP using the exchanged key
        generated_otp = auth.generate_otp(user.client_public_key)
        flash(f'Generated OTP: {generated_otp}', 'success')
    return render_template('generate_otp.html', form=form, user=user)  # Pass user to the template

@app.route('/key_exchange', methods=['GET', 'POST'])
def key_exchange():
    form = KeyExchangeForm()
    if form.validate_on_submit():
        client_public_key = int(form.client_public_key.data)

        shared_secret_client = auth.calculate_shared_secret(auth.public_key_server, client_public_key)

        flash('Key exchange successful!', 'success')
        return redirect(url_for('generate_otp'))

    return render_template('key_exchange.html', form=form)


@app.route('/generate_qr_code', methods=['GET'])
def generate_qr_code():
    user = User.query.filter_by(username=session['username']).first()

    # Check if QR code image is already generated and saved
    if user.qr_code_image:
        qr_code_img = user.qr_code_image
    else:
        # Create a TOTP object using the user's OTP secret
        totp = pyotp.TOTP(user.otp_secret)
        otp_uri = totp.provisioning_uri(user.username, issuer_name="YourApp")

        # Generate QR code
        img = qrcode.make(otp_uri)
        qr_code_img = BytesIO()
        img.save(qr_code_img, format='PNG')

        # Save the QR code image to the user's record in the database
        user.qr_code_image = qr_code_img.getvalue()
        db.session.commit()

    return render_template('generate_qr_code.html', qr_code=qr_code_img.getvalue())

@app.route('/generate_qr', methods=['GET', 'POST'])
def generate_qr():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    global auth
    if auth is None:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()

    # Generate a 6-digit verification key
    verification_key = generate_6_digit_key()
    session['verification_key'] = verification_key

    # Store the verification key as the generated key
    session['generated_key'] = verification_key

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(verification_key)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")

    # Save QR code image to the static/qr_codes directory with the username and login count
    qr_img_filename = f'{user.username}_{user.login_count}_qr_code.png'
    qr_img_path = os.path.join(app.root_path, 'static', 'qr_codes', qr_img_filename)
    qr_img.save(qr_img_path)

    return render_template('generate_qr.html', qr_img_filename=qr_img_filename)

@app.route('/verify_key', methods=['POST'])
def verify_key():
    entered_key = request.form.get('verification_key')
    expected_key = session.get('verification_key')

    if entered_key == expected_key:
        # Store the generated key in the database
        username = session['username']
        generated_key = session['generated_key']

        key_entry = GeneratedKey(username=username, generated_key=generated_key)
        db.session.add(key_entry)
        db.session.commit()

        # Retrieve the user information from the database
        user = User.query.filter_by(username=username).first()

        # Verification successful, render the profile.html template
        return render_template('profile.html', user=user)
    else:
        flash('Verification failed. Incorrect key.', 'error')
        return redirect(url_for('generate_qr'))

@app.route('/verify_identifier/<string:scanned_identifier>', methods=['GET'])
def verify_identifier(scanned_identifier):
    if session.get('identifier') == scanned_identifier:
        flash('User verified successfully!', 'success')
    else:
        flash('Invalid identifier.', 'error')

    return redirect(url_for('generate_qr'))

# In your Flask app
password = db.Column(db.String(120), nullable=False)

# In your Flask app
class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    age = StringField('Age')
    gender = StringField('Gender', validators=[DataRequired()])
    address = StringField('Address')
    submit = SubmitField('Save Changes')

    @app.route('/profile/<username>', methods=['GET'])
    def profile(username):
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('profile.html', user=user)
        else:
            flash('User not found', 'error')
            return redirect(url_for('index'))


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if not session.get('logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    username = session['username']
    user = User.query.filter_by(username=username).first()

    form = EditProfileForm(obj=user)

    if form.validate_on_submit():
        user.username = form.username.data
        user.phone_number = form.phone_number.data
        user.email = form.email.data
        user.age = form.age.data
        user.gender = form.gender.data
        user.address = form.address.data
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile', username=username))

    return render_template('edit_profile.html', form=form, user=user)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)