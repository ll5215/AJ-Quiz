import os
MONGO_URI = 'mongodb://aj:jungleaj@43.203.204.187:27017/admin'
SECRET_KEY = os.urandom(24)
JWT_SECRET_KEY = 'your_jwt_secret_key'  # 임의의 비밀 키 설정