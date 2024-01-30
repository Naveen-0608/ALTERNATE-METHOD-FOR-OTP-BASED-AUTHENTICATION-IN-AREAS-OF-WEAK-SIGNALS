from flask import Flask, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request
from wtforms import StringField, DateField
from wtforms.validators import DataRequired
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = '0000'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///navee.sqlite3'
db = SQLAlchemy(app)

class Use(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    aadhar_number = db.Column(db.String(12), unique=True, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class GeneratedKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), db.ForeignKey('use.username'), nullable=False)  # Use the username as the reference
    generated_key = db.Column(db.String(6), nullable=False)

db.create_all()

class UserDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('use.id'), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    date_of_birth = db.Column(db.String(10), nullable=False)

db.create_all()

class ProfileDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('use.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    aadhar_number = db.Column(db.String(12), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    date_of_birth = db.Column(db.String(10), nullable=False)

db.create_all()

def generate_6_digit_key():
    return ''.join(random.choice('0123456789') for _ in range(6))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    aadhar_number = StringField('Aadhar Number', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UserDetailsForm(FlaskForm):
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    date_of_birth = StringField('Date of Birth', validators=[DataRequired()])
    submit = SubmitField('Submit')


@app.route('/')
def index():
    return render_template('index1.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if the username already exists
        existing_user = Use.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'danger')
        else:
            # Create and add the new user
            user = Use(
                username=form.username.data,
                aadhar_number=form.aadhar_number.data,
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
    return render_template('register1.html', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Use.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))

        # Generate a 6-digit verification key
        verification_key = generate_6_digit_key()

        # Store the generated key in the database
        key_record = GeneratedKey(username=user.username, generated_key=verification_key)
        db.session.add(key_record)
        db.session.commit()

        # Store the username in the session for later use
        session['username'] = user.username

        # Redirect to the verification page after successful login
        return redirect(url_for('verify'))

    return render_template('login1.html', form=form)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    verification_result = None

    if request.method == 'POST':
        user = Use.query.filter_by(username=session['username']).first()
        key_record = GeneratedKey.query.filter_by(username=user.username).order_by(GeneratedKey.id.desc()).first()

        if key_record:
            expected_key = key_record.generated_key
            received_key = request.form.get('verification_key')

            if received_key == expected_key:
                verification_result = True
                return redirect(url_for('user_details'))
            else:
                verification_result = False

    return render_template('verify.html', verification_result=verification_result)

# ... (other code)

@app.route('/user_details', methods=['GET', 'POST'])
def user_details():
    form = UserDetailsForm()
    if form.validate_on_submit():
        user = Use.query.filter_by(username=session['username']).first()
        user_details = UserDetails(
            user_id=user.id,
            phone_number=form.phone_number.data,
            address=form.address.data,
            date_of_birth=form.date_of_birth.data
        )
        db.session.add(user_details)
        db.session.commit()

        return redirect(url_for('profile'))  # Redirect to the appropriate page

    user = Use.query.filter_by(username=session['username']).first()  # Fetch the user
    profile_data = {
        'username': user.username,
        'aadhar_number': user.aadhar_number,
        'phone_number': '',
        'address': '',
        'date_of_birth': ''
    }

    return render_template('details.html', user=user, profile_data=profile_data, form=form)

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = Use.query.filter_by(username=username).first()  # Fetch the user
    user_details = UserDetails.query.filter_by(user_id=user.id).first()

    if user_details is None:
        return redirect(url_for('details'))

    profile_data = {
        'username': user.username,
        'aadhar_number': user.aadhar_number,
        'phone_number': user_details.phone_number,
        'address': user_details.address,
        'date_of_birth': user_details.date_of_birth,
    }
    return render_template('profile1.html', user=user, profile_data=profile_data)

if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', port=5002, debug=True)
