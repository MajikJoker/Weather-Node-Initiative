from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from pymongo import MongoClient
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import os
from flask_mail import Mail, Message
from flask import Flask, request, jsonify
import random
from flask_cors import CORS



# Load environment variables from .env file
load_dotenv()

# MongoDB connection
mongo_uri = os.environ.get('MONGO_URI')
client = MongoClient(mongo_uri)
print(mongo_uri)

# Adding in database and collection from MongoDB Atlas
db = client["userManagement"]
users = db["users"]

# Instantiating new object with "name"
app = Flask(__name__)
CORS(app)

@app.route('/proxy/climate-historical', methods=['OPTIONS', 'POST'])
def proxy_climate_historical():
    if request.method == 'OPTIONS':
        # Handle preflight CORS request
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
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

    return jsonify(response.json()), response.status_code

@app.route('/proxy/warningbar', methods=['OPTIONS', 'POST'])
def proxy_warningbar():
    if request.method == 'OPTIONS':
        # Handle preflight CORS request
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
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

    return jsonify(response.json()), response.status_code

# Secret key
app.secret_key = os.environ.get('SECRET_KEY')

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
# app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS') == 'True'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

mail = Mail(app)

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

# @app.route('/secadmin')
# @role_required('secadmin')
# def secadmin():
#     return render_template('securityAdmin.html')

@app.route('/weather', methods=['POST'])
def get_weather():
    data = request.json
    latitude = data['latitude']
    longitude = data['longitude']
    api_key="827db554784d6d5cd704af90e92577b4"
    
    # Define the API endpoint URL with placeholders
    url = f"https://api.openweathermap.org/data/2.5/weather?lat={latitude}&lon={longitude}&appid={api_key}"

    # Send a GET request to the API endpoint
    response = requests.get(url)

    # Check for successful response (status code 200)
    if response.status_code == 200:
        # Convert the JSON response to a Python dictionary
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
            # Generate a random 4-digit code
            two_fa_code = random.randint(1000, 9999)

            # Send the 4-digit code to the user's email
            try:
                msg = Message('Your 2FA Code', sender=os.environ.get('MAIL_USERNAME'), recipients=[email])
                msg.body = f'Your 2FA code is {two_fa_code}.'
                mail.send(msg)
            except Exception as e:
                flash(f"Failed to send email: {str(e)}")
                return redirect(url_for('home'))

            # Save the 2FA code in the session
            session['2fa_code'] = str(two_fa_code)
            session['temp_user'] = email

            return redirect(url_for('verify_2fa'))

        else:
            flash("Invalid email or password")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_user' not in session or '2fa_code' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_code = request.form.get('2fa_code')

        if entered_code == session['2fa_code']:
            # Move the user from temp_user to logged in user
            session['user'] = session.pop('temp_user')
            session.pop('2fa_code', None)

            # Redirect based on user role
            user = users.find_one({"email": session['user']})
            if user.get('role') == 'sysadmin':
                return redirect(url_for('sysadmin_dashboard'))
            elif user.get('role') == 'secadmin':
                return redirect(url_for('secadmin_dashboard'))
            else:
                return redirect(url_for('loggedhome'))

        else:
            flash("Invalid 2FA code")
            return redirect(url_for('verify_2fa'))

    return render_template('verify_2fa.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = 'free_user'  # Default role is 'free_user'

        if users.find_one({"email": email}):
            flash("Email already exists")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='sha256')
        user_data = {
            "first_name": first_name,
            "email": email,
            "password": hashed_password,
            "role": role  # Include role in user data
        }

        try:
            users.insert_one(user_data)
            flash("Registration successful! You can now log in.")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/loggedhome')
def loggedhome():
    if 'user' in session:
        email = session['user']
        user = users.find_one({"email": email})
        if user:
            first_name = user.get('first_name', 'User')
            return render_template('loggedhome.html', first_name=first_name, user=user)
        else:
            flash("User not found")
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/sysadmin_dashboard')
@role_required('sysadmin')
def sysadmin_dashboard():
    return render_template('sysadmin.html')

@app.route('/secadmin_dashboard')
@role_required('secadmin')
def secadmin_dashboard():
    return render_template('securityAdmin.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))


# Helper functions
def generate_small_rsa_keys():
    # Generate small RSA keys for simplicity
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = modinv(e, phi)
    return (n, e), d

def modinv(a, m):
    # Compute the modular inverse of a modulo m
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def compute_small_hash(data):
    # Compute a simple hash function for the data
    return sum(bytearray(data.encode('utf-8'))) % 100

# Key generation
public_key, d = generate_small_rsa_keys()
n, e = public_key

# User identity hash computation
def compute_private_key_for_id(identity):
    H_ID = compute_small_hash(identity)
    DID = pow(H_ID, d, n)
    return DID

# Signing a message
def sign_message(identity, message):
    DID = compute_private_key_for_id(identity)
    H_M = compute_small_hash(message)
    sigma = (H_M * DID) % n
    return sigma

# Aggregation of signatures
def aggregate_signatures(signatures):
    sigma_agg = 1
    for sigma in signatures:
        sigma_agg = (sigma_agg * sigma) % n
    return sigma_agg

# Verification of aggregated signature
def verify_aggregate_signature(identities, messages, sigma_agg):
    P_agg = 1
    H_M_prod = 1
    for identity, message in zip(identities, messages):
        H_ID = compute_small_hash(identity)
        H_M = compute_small_hash(message)
        P_agg = (P_agg * H_ID) % n
        H_M_prod = (H_M_prod * H_M) % n

    left = pow(sigma_agg, e, n)
    right = (H_M_prod * P_agg) % n

    return left == right

@app.route('/ibas')
def index():
    identities = ["Open Weather	", "Weather Gov	"]
    messages = ["827db554784d6d5cd704af90e92577b4", "NA"]

    # Generate individual signatures
    signatures = [sign_message(identity, message) for identity, message in zip(identities, messages)]

    # Aggregate signatures
    sigma_agg = aggregate_signatures(signatures)

    # Verify aggregated signature
    is_valid = verify_aggregate_signature(identities, messages, sigma_agg)

    # Collect results for display
    results = {
        "identities": identities,
        "messages": messages,
        "signatures": signatures,
        "aggregated_signature": sigma_agg,
        "is_valid": is_valid,
        "n": n,
        "e": e,
        "d": d,
    }

    # Add individual intermediate values for debugging
    for i, (identity, message) in enumerate(zip(identities, messages)):
        H_ID = compute_small_hash(identity)
        DID = compute_private_key_for_id(identity)
        H_M = compute_small_hash(message)
        results[f"H_ID_{i+1}"] = H_ID
        results[f"DID_{i+1}"] = DID
        results[f"H_M_{i+1}"] = H_M

    return render_template('ibas.html', results=results)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
