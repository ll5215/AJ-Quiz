import os
MONGO_URI = 'mongodb://localhost:27017/user_database'
SECRET_KEY = os.urandom(24)
JWT_SECRET_KEY = 'your_jwt_secret_key'  # 임의의 비밀 키 설정