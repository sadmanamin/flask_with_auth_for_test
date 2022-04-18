import os


class Config:
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://postgres:123456@localhost:5432/flask_with_token'
    SQLALCHEMY_TRACK_MODIFICATIONS = False