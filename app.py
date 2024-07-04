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
    questions = list(db.questions.find({'user': current_user['username']}))
    for question in questions:
        question['_id'] = str(question['_id'])  # ObjectId를 문자열로 변환
    return render_template('mypage.html', username=current_user['username'], questions=questions)

@app.route('/card-detail')
@token_required
def card_detail(current_user):
    question = request.args.get('question')
    answer = request.args.get('answer')
    user_answer = request.args.get('user_answer')
    views = request.args.get('views')
    correct = request.args.get('correct') == 'true'
    question_id = request.args.get('question_id')
    return render_template('card-detail.html', username=current_user['username'], question=question, answer=answer, user_answer=user_answer, views=views, correct=correct, question_id=question_id)

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if data is None:
            return jsonify({'message': 'No input data provided'}), 400
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        if db.users.find_one({'username': username}):
            return jsonify({'message': 'Username already exists'}), 409

        hashed_password = generate_password_hash(password)
        db.users.insert_one({'username': username, 'password': hashed_password})
        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        logging.error(f"Registration error: {e}")
        return jsonify({'message': f"Internal server error: {e}"}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            if data is None:
                return jsonify({'message': 'No input data provided'}), 400
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                return jsonify({'message': 'Username and password are required'}), 400

            logging.info(f"Attempting login for username: {username}")
            user = db.users.find_one({'username': username})
            if not user:
                logging.warning(f"Invalid username: {username}")
                return jsonify({'message': 'Invalid username'}), 401
            if not check_password_hash(user['password'], password):
                logging.warning(f"Invalid password for username: {username}")
                return jsonify({'message': 'Invalid password'}), 401
            payload = {
                'username': username,
                'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
            }
            logging.info(f"Payload: {payload}")
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
            resp = make_response(jsonify({'message': 'Login successful'}))
            resp.set_cookie('access_token', token, httponly=True)
            return resp
        except Exception as e:
            logging.error(f"Login error: {e}")
            return jsonify({'message': f"Internal server error: {e}"}), 500
    return render_template('login.html')
    
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('access_token', '', expires=0)
    return resp

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
    questions = list(db.questions.find())  # 모든 질문을 가져옴
    for question in questions:
        question['_id'] = str(question['_id'])  # ObjectId를 문자열로 변환
    return jsonify({'success': True, 'questions': questions}), 200

@app.route('/submit-answer', methods=['POST'])
@token_required
def submit_answer(current_user):
    data = request.get_json()
    question_id = data.get('question_id')
    user_answer = data.get('answer')
    
    if not question_id or not user_answer:
        return jsonify({'success': False, 'message': 'Missing question ID or answer'}), 400

    existing_answer = db.answers.find_one({
        'question_id': ObjectId(question_id),
        'user': current_user['username']
    })

    if existing_answer:
        return jsonify({'success': False, 'message': 'Answer already submitted'}), 400

    new_answer = {
        'question_id': ObjectId(question_id),
        'user': current_user['username'],
        'answer': user_answer,
        'likes': 0
    }

    db.answers.insert_one(new_answer)
    new_answer['_id'] = str(new_answer['_id'])  # ObjectId를 문자열로 변환
    new_answer['question_id'] = str(new_answer['question_id'])  # ObjectId를 문자열로 변환

    return jsonify({'success': True, 'newAnswer': new_answer}), 200

@app.route('/get-user-answers', methods=['GET'])
@token_required
def get_user_answers(current_user):
    user_answers = list(db.answers.find({'user': current_user['username']}))
    for answer in user_answers:
        answer['_id'] = str(answer['_id'])  # ObjectId를 문자열로 변환
        answer['question_id'] = str(answer['question_id'])  # ObjectId를 문자열로 변환
    return jsonify({'success': True, 'userAnswers': user_answers}), 200

@app.route('/edit/questions', methods=["POST"])
@token_required
def edit_questions(current_user):
    data = request.get_json()
    question_id = data.get('question_id')
    question_receieve = data.get('question')
    answer_receieve = data.get('answer')
    
    result = db.questions.update_one({'_id': ObjectId(question_id), 'user': current_user['username']},
                                     {'$set': {'question': question_receieve, 'answer': answer_receieve}})
    if result.modified_count == 1:
        return jsonify({'result': 'success'})
    else:
        return jsonify({'result': 'failure'})

@app.route('/delete/questions', methods=["POST"])
@token_required
def delete_questions(current_user):
    data = request.get_json()
    question_id = data.get('question_id')
    result = db.questions.delete_one({'_id': ObjectId(question_id), 'user': current_user['username']})
    
    if result.deleted_count == 1:
        return jsonify({'result': 'success'})
    else:
        return jsonify({'result': 'failure'})

@app.route('/get-question-answers/<question_id>', methods=['GET'])
@token_required
def get_question_answers(current_user, question_id):
    answers = list(db.answers.find({'question_id': ObjectId(question_id)}).sort('likes', -1))  # 좋아요 수로 내림차순 정렬
    user_likes = list(db.likes.find({'user_id': current_user['_id']}))
    liked_answers = [str(like['answer_id']) for like in user_likes]
    
    for answer in answers:
        answer['_id'] = str(answer['_id'])  # ObjectId를 문자열로 변환
        answer['question_id'] = str(answer['question_id'])  # ObjectId를 문자열로 변환
        answer['liked'] = answer['_id'] in liked_answers  # 사용자가 좋아요를 눌렀는지 여부 확인
    
    return jsonify({'success': True, 'answers': answers}), 200

@app.route('/like-answer', methods=['POST'])
@token_required
def like_answer(current_user):
    data = request.json
    answer_id = data.get('answer_id')
    
    if answer_id:
        db.answers.update_one({'_id': ObjectId(answer_id)}, {'$inc': {'likes': 1}})
        db.likes.insert_one({'user_id': current_user['_id'], 'answer_id': ObjectId(answer_id)})
        answer = db.answers.find_one({'_id': ObjectId(answer_id)})
        return jsonify({"success": True, "likes": answer['likes']})
    return jsonify({"success": False, "error": "Answer not found"}), 404

@app.route('/unlike-answer', methods=['POST'])
@token_required
def unlike_answer(current_user):
    data = request.json
    answer_id = data.get('answer_id')
    
    if answer_id:
        db.answers.update_one({'_id': ObjectId(answer_id)}, {'$inc': {'likes': -1}})
        db.likes.delete_one({'user_id': current_user['_id'], 'answer_id': ObjectId(answer_id)})
        answer = db.answers.find_one({'_id': ObjectId(answer_id)})
        return jsonify({"success": True, "likes": answer['likes']})
    return jsonify({"success": False, "error": "Answer not found"}), 404

@app.route('/update-views/<question_id>', methods=['POST'])
@token_required
def update_views(current_user, question_id):
    db.questions.update_one({'_id': ObjectId(question_id)}, {'$inc': {'views': 1}})
    return jsonify({'success': True}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
