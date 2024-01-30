from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()
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
    qr_code_image = db.Column(db.LargeBinary)  # For QR code image storage
    otp_secret = db.Column(db.String(16))  # For OTP secret storage

db = SQLAlchemy()
class GeneratedKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)  # Use the username as the reference
    generated_key = db.Column(db.String(6), nullable=False)

    # Define the relationship with the Use model
    user = db.relationship('Use', backref='generated_keys')
