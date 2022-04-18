from flask import Flask, request, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
import jwt

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()

    def encode_token(self):
        # private_key = open('test').read()
        payload = {
            'user_id': self.id
        }
        token = jwt.encode(payload, 'my-secret', algorithm='HS256').decode('utf-8')
        return token

    def decode_token(self, token):
        # public_key = open('test.pub').read()
        # print(public_key)
        payload = jwt.decode(token, 'my-secret', algorithms=['HS256'])
        return payload.get('user_id')

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    title = db.Column(db.String(100))
    complete = db.Column(db.Boolean)
    
    def __init__(self, user_id, title):
        self.user_id = user_id
        self.title = title
        self.complete = False

def decode_token(token):
    # public_key = open('test.pub').read()
    # print(public_key)
    try:
        payload = jwt.decode(token, 'my-secret', algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return 'expired'
    except jwt.InvalidTokenError:
        return 'invalid'
    except Exception as e:
        app.logger.info(e)
        return 'invalid'


@app.route('/sign_up', methods=["POST"])
def sign_up():
    post_data = request.get_json()

    name = post_data.get('name')
    email = post_data.get('email')
    password = post_data.get('password')

    user = User.query.filter_by(
        email=email).first()

    if not user:
        new_user = User(
            name = name,
            email = email,
            password = password
        )
        db.session.add(new_user)
        db.session.commit()

        responseObject = {
            'status': 'success',
            'message': 'User registered.'
        }
        return make_response(jsonify(responseObject)), 201
    else:
        responseObject = {
            'status': 'fail',
            'message': 'User exists.'
        }
        return make_response(jsonify(responseObject)), 400


@app.route('/sign_in', methods=["POST"])
def sign_in():
    post_data = request.get_json()

    email = post_data.get('email')
    password = post_data.get('password')

    user = User.query.filter_by(
        email=post_data.get('email')
    ).first()

    if user and bcrypt.check_password_hash(user.password, post_data.get('password')):
        token = user.encode_token()

        responseObject = {
            'status': 'success',
            'message': 'Logged In.',
            'token': token
        }
        return make_response(jsonify(responseObject)), 201

    else:
        responseObject = {
            'status': 'fail',
            'message': 'Failed to login.'
        }
        return make_response(jsonify(responseObject)), 400

@app.route('/add_todo', methods=["POST"])
def add_todo():
    post_data = request.get_json()
    auth_header = request.headers.get('Authorization')

    title = post_data.get('title')

    # AUTH #
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''
    app.logger.info(auth_token)
    resp = decode_token(auth_token)
    user_id = resp
    if resp == 'invalid' or resp == 'expired':
        responseObject = {
            'status': 'fail',
            'message': 'Failed to authenticate.'
        }
        return make_response(jsonify(responseObject)), 400
    # AUTH #

    todo = Todo(
        user_id=user_id,
        title=title
    )

    db.session.add(todo)
    db.session.commit()

    responseObject = {
        'status': 'success',
        'message': 'Todo added.'
    }
    return make_response(jsonify(responseObject)), 201

@app.debug('/alive')
def alive():
    return 'Success'