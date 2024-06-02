from flask import Flask, render_template, request, redirect, url_for
from pymongo import MongoClient

app = Flask(__name__)

# MongoDB connection
client = MongoClient("mongodb+srv://bhone:ASbtsVpm5fnUd6wv@test.5zngklh.mongodb.net/userManagement")
db = client.userManagement
users_collection = db.users

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users_collection.find_one({'username': username, 'password': password})
        if user:
            return redirect(url_for('logged_home'))
        else:
            return "Invalid username or password"
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if users_collection.find_one({'username': username}):
            return "Username already exists"
        
        users_collection.insert_one({'username': username, 'password': password})
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/loggedhome')
def logged_home():
    return render_template('loggedhome.html')

if __name__ == '__main__':
    app.run(debug=True)
