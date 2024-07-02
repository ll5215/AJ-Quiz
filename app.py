from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt

app = Flask(__name__)
app.config.from_pyfile('config.py')

client = MongoClient(app.config['MONGO_URI'])
db = client.user_database
SECRET_KEY = app.config['JWT_SECRET_KEY']

def token_required(f):
    def wrap(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = db.users.find_one({'username': data['username']})
        except Exception as e:
            return jsonify({'message': f'Token is invalid! {e}'}), 401
        return f(current_user, *args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        db.users.insert_one({'username': username, 'password': hashed_password})
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        password = data['password']
        user = db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            payload = {
                'username': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
            resp = make_response(jsonify({'message': 'Login successful'}))
            resp.set_cookie('access_token', token, httponly=True)
            return resp
        return jsonify({'message': 'Invalid credentials'}), 401
    return render_template('login.html')

@app.route('/main')
@token_required
def main(current_user):
    return render_template('main.html', username=current_user['username'])

if __name__ == '__main__':
    app.run(debug=True)