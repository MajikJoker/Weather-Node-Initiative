from flask import Flask, render_template, request, redirect, url_for
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# MongoDB connection
uri = "mongodb+srv://bhone:<password>@test.5zngklh.mongodb.net/?retryWrites=true&w=majority&appName=test"

client = MongoClient(uri, server_api=ServerApi('1'))
db = client['test']  # Replace 'test' with your database name
users_collection = db['users']  # Replace 'users' with your collection name

# Ensure connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve user from MongoDB
        user = users_collection.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            return f"Welcome, {username}!"
        else:
            return "Invalid username or password. Please try again."
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        if users_collection.find_one({'username': username}):
            return "Username already exists. Please choose another one."
        else:
            # Hash the password before storing it
            hashed_password = generate_password_hash(password, method='sha256')
            users_collection.insert_one({'username': username, 'password': hashed_password})
            return redirect(url_for('login'))
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
