from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
from pymongo import MongoClient
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import os
from flask_mail import Mail, Message
from flask_cors import CORS
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import base64
import random

# Load environment variables from .env file
load_dotenv()

# MongoDB connection
mongo_uri = os.environ.get('MONGO_URI')
client = MongoClient(mongo_uri)
db = client["userManagement"]
users = db["users"]
weather_data_db = client["weather_data"]

# Flask app initialization
app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY')

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS') == 'True'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

mail = Mail(app)

# Load server's private key (for example purposes, normally you store it securely)
with open("server_private_key.pem", "rb") as key_file:
    server_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

# Load data source's public key (for example purposes)
with open("data_source_public_key.pem", "rb") as key_file:
    data_source_public_key = serialization.load_pem_public_key(
        key_file.read()
    )

# Function to sign data
def sign_data(data, private_key):
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# Function to verify signature
def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            base64.b64decode(signature),
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

# Weather routes
@app.route('/get_weather', methods=['POST'])
def get_weather():
    data = request.json
    latitude = data['latitude']
    longitude = data['longitude']
    api_key = os.environ.get('WEATHER_API_KEY')

    url = f"https://api.openweathermap.org/data/2.5/weather?lat={latitude}&lon={longitude}&appid={api_key}"
    response = requests.get(url)

    if response.status_code == 200:
        weather_data = response.json()
        data_str = str(weather_data)
        signature = sign_data(data_str, server_private_key)

        weather_data_db.weather.insert_one({
            "data": weather_data,
            "signature": signature,
            "public_key": base64.b64encode(data_source_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode(),
            "data_hash": base64.b64encode(hashes.Hash(hashes.SHA256()).update(data_str.encode()).finalize()).decode(),
            "signature_hash": base64.b64encode(hashes.Hash(hashes.SHA256()).update(signature.encode()).finalize()).decode()
        })
        return jsonify(weather_data)
    else:
        return jsonify({
            "error": f"API request failed with status code {response.status_code}",
            "message": response.text
        }), response.status_code

@app.route('/retrieve_weather', methods=['GET'])
def retrieve_weather():
    weather_record = weather_data_db.weather.find_one(sort=[('_id', -1)])  # Retrieve the latest record

    if weather_record:
        data_str = str(weather_record['data'])
        data_hash = base64.b64encode(hashes.Hash(hashes.SHA256()).update(data_str.encode()).finalize()).decode()
        signature_hash = base64.b64encode(hashes.Hash(hashes.SHA256()).update(weather_record['signature'].encode()).finalize()).decode()

        if data_hash == weather_record['data_hash'] and signature_hash == weather_record['signature_hash']:
            public_key = serialization.load_pem_public_key(
                base64.b64decode(weather_record['public_key'])
            )
            if verify_signature(data_str, weather_record['signature'], public_key):
                return jsonify(weather_record['data'])
            else:
                return jsonify({"error": "Signature verification failed"}), 400
        else:
            return jsonify({"error": "Data integrity check failed"}), 400
    else:
        return jsonify({"error": "No weather data found"}), 404

# Proxy routes
@app.route('/proxy/climate-historical', methods=['OPTIONS', 'POST'])
def proxy_climate_historical():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'OK'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        return response, 204

    url = "https://www.weather.gov.sg/wp-content/themes/wiptheme/page-functions/functions-climate-historical-daily-records.php"
    headers = {'Content-Type': 'application/json'}
    data = request.get_json()

    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

    return jsonify(response.json()), response.status_code

@app.route('/proxy/warningbar', methods=['OPTIONS', 'POST'])
def proxy_warningbar():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'OK'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        return response, 204

    url = "https://www.weather.gov.sg/wp-content/themes/wiptheme/page-functions/functions-ajax-warningbar.php"
    headers = {'Content-Type': 'application/json'}
    data = request.get_json()

    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

    return jsonify(response.json()), response.status_code

# Authentication and role management
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                flash("You need to be logged in to access this page.")
                return redirect(url_for('login'))

            user = users.find_one({"email": session['user']})
            if user is None or user.get('role') != required_role:
                flash("You do not have the required permissions to access this page.")
                return redirect(url_for('home'))

            g.user = user  # Add user to global context
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/history')
def history():
    return render_template('historydata.html')

@app.route('/current')
def current():
    return render_template('currentdata.html')

@app.route('/weather', methods=['POST'])
def weather():
    data = request.json
    latitude = data['latitude']
    longitude = data['longitude']
    api_key = "827db554784d6d5cd704af90e92577b4"
    
    url = f"https://api.openweathermap.org/data/2.5/weather?lat={latitude}&lon={longitude}&appid={api_key}"

    response = requests.get(url)

    if response.status_code == 200:
        weather_data = response.json()
        return jsonify(weather_data)
    else:
        return jsonify({
            "error": f"API request failed with status code {response.status_code}",
            "message": response.text
        }), response.status_code

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = users.find_one({"email": email})

        if user and check_password_hash(user['password'], password):
            two_fa_code = random.randint(1000, 9999)

            try:
                msg = Message('Your 2FA Code', sender=os.environ.get('MAIL_USERNAME'), recipients=[email])
                msg.body = f"Your 2FA code is {two_fa_code}"
                mail.send(msg)
            except Exception as e:
                flash("Failed to send 2FA code. Please try again.")
                return render_template('login.html')

            session['2fa_user_id'] = str(user['_id'])
            session['2fa_code'] = two_fa_code
            return redirect(url_for('two_factor_auth'))

        flash("Invalid email or password. Please try again.")
        return render_template('login.html')
    return render_template('login.html')

@app.route('/two-factor-auth', methods=['GET', 'POST'])
def two_factor_auth():
    if request.method == 'POST':
        user_id = session.get('2fa_user_id')
        user = users.find_one({"_id": ObjectId(user_id)})

        if user and request.form.get('2fa_code') == str(session.get('2fa_code')):
            session.pop('2fa_user_id', None)
            session.pop('2fa_code', None)
            session['user'] = user['email']
            return redirect(url_for('dashboard'))

        flash("Invalid 2FA code. Please try again.")
        return render_template('two_factor_auth.html')
    return render_template('two_factor_auth.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if users.find_one({"email": email}):
            flash("Email address already registered.")
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='sha256')
        users.insert_one({"email": email, "password": hashed_password, "role": "user"})
        flash("Registration successful. Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        user = users.find_one({"email": session['user']})
        return render_template('dashboard.html', user=user)
    else:
        flash("You need to be logged in to access this page.")
        return redirect(url_for('login'))

@app.route('/admin')
@role_required('admin')
def admin_dashboard():
    return render_template('admin.html')

@app.route('/profile')
def profile():
    if 'user' in session:
        user = users.find_one({"email": session['user']})
        return render_template('profile.html', user=user)
    else:
        flash("You need to be logged in to access this page.")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
