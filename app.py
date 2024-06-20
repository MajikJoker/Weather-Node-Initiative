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
# Create CORS object
cors = CORS()

# Apply CORS to app
cors.init_app(app, resources={r"/*": {"origins": "*"}})


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
    return render_template('secadmin.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
