from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt
import logging
from bson.objectid import ObjectId

app = Flask(__name__)
app.config.from_pyfile('config.py')
client = MongoClient(app.config['MONGO_URI'])
db = client.aj
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
@app.route('/mypage', methods=['GET', 'POST'])
@token_required
def mypage(current_user):
    return render_template('mypage.html', username=current_user['username'])
@app.route('/card-detail')
@token_required
def card_detail(current_user):
    return render_template('card-detail.html', username=current_user['username'])
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
        data = request.get_json()  # JSON 데이터 수신
        username = data.get('username')
        password = data.get('password')
        user = db.users.find_one({'username': username})
        if not user:
            return jsonify({'message': 'Invalid username'}), 401
        if not check_password_hash(user['password'], password):
            return jsonify({'message': 'Invalid password'}), 401
        payload = {
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }
        logging.info(payload)
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        resp = make_response(jsonify({'message': 'Login successful'}))
        resp.set_cookie('access_token', token, httponly=True)
        return resp
    return render_template('login.html')
@app.route('/main')
@token_required
def main(current_user):
    return render_template('main.html', username=current_user['username'])

@app.route('/add-question', methods=['POST'])
@token_required
def add_question(current_user):
    data = request.get_json()
    question = data.get('question')
    answer = data.get('answer')

    if not question or not answer:
        return jsonify({'success': False, 'message': 'Missing question or answer'}), 400

    new_question = {
        'question': question,
        'answer': answer,
        'views': 0,
        'user': current_user['username']
    }

    inserted_id = db.questions.insert_one(new_question).inserted_id
    new_question['_id'] = str(inserted_id)  # Convert ObjectId to string

    return jsonify({'success': True, 'newQuestion': new_question}), 200

@app.route('/get-questions', methods=['GET'])
@token_required
def get_questions(current_user):
    questions = list(db.questions.find({'user': current_user['username']}))
    for question in questions:
        question['_id'] = str(question['_id'])  # Convert ObjectId to string
    return jsonify({'success': True, 'questions': questions}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=3000)
