from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# MongoDB connection
mongo_uri = os.environ.get('MONGO_URI')
client = MongoClient(mongo_uri)

# Adding in database and collection from MongoDB Atlas
db = client["userManagement"]
users = db["users"]

# Instantiating new object with "name"
app = Flask(__name__)

# Secret key
app.secret_key = os.environ.get('SECRET_KEY')

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = users.find_one({"email": email})

        if user and check_password_hash(user['password'], password):
            session['user'] = email

            # Redirect based on user role
            if user.get('role') == 'sysadmin':
                return redirect(url_for('sysadmin_dashboard'))
            elif user.get('role') == 'secadmin':
                return redirect(url_for('secadmin_dashboard'))
            else:
                return redirect(url_for('loggedhome'))
        else:
            flash("Invalid email or password")
            return redirect(url_for('login'))

    return render_template('login.html')

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
