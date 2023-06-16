from flask import Flask
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_cors import CORS
import jwt

app = Flask(__name__)# Instantiation of Flask object.
CORS(app)
api = Api(app)  # Instantiation of Flask-RESTX object.

############################
##### BEGIN: Database #####
##########################
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/deteksikendaraan"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

db = SQLAlchemy(app)  # Instantiation of Flask-SQLAlchemy object.


class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    email = db.Column(db.String(32), unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(256), nullable=False)

@app.route("/api/create_user", methods=["GET"])
def user_db():
    with app.app_context():
        db.create_all()
        return "Database User Telah dibuat" + ' <a href="/"> Kembali</a>'


##########################
##### END: Database #####
########################

###########################
##### BEGIN: register #####
#########################
parser4Register = reqparse.RequestParser()
parser4Register.add_argument('email', type=str, help='Email', location='json', required=True)
parser4Register.add_argument('name', type=str, help='Name', location='json', required=True)
parser4Register.add_argument('password', type=str, help='Password', location='json', required=True)
parser4Register.add_argument('re_password', type=str, help='Retype Password', location='json', required=True)


@api.route('/register')
class Registration(Resource):
    @api.expect(parser4Register)
    def post(self):
        # BEGIN: Get request parameters.
        args = parser4Register.parse_args()
        email = args['email']
        name = args['name']
        password = args['password']
        rePassword = args['re_password']
        # END: Get request parameters.

        # BEGIN: Check re_password.
        if password != rePassword:
            return {
                       'messege': 'Password must be the same!'
                   }, 400
        # END: Check re_password.

        # BEGIN: Check email existance.
        user = db.session.execute(db.select(User).filter_by(email=email)).first()
        if user:
            return {
                       'messege': 'This email address has been used!'
                   }, 400
        # END: Check email existance.

        # BEGIN: Insert new user.
        user = User()  # Instantiate User object.
        user.email = email
        user.name = name
        user.password = generate_password_hash(password)

        db.session.add(user)
        db.session.commit()
        # END: Insert new user.

        return {'messege': 'Successful!'}, 201


#########################
##### END: register #####
#######################

###########################
##### BEGIN: login #####
#########################
SECRET_KEY = "WhatEverYouWant"
ISSUER = "myFlaskWebservice"
AUDIENCE_MOBILE = "myMobileApp"

parser4LogIn = reqparse.RequestParser()
parser4LogIn.add_argument('email', type=str, help='Email', location='json', required=True)
parser4LogIn.add_argument('password', type=str, help='Password', location='json', required=True)


@api.route('/login')
class LogIn(Resource):
    @api.expect(parser4LogIn)
    def post(self):
        # BEGIN: Get request parameters.
        args = parser4LogIn.parse_args()
        email = args['email']
        password = args['password']
        # END: Get request parameters.

        if not email or not password:
            return {
                       'message': 'Please fill your email and password!'
                   }, 400

        # BEGIN: Check email existance.
        user = db.session.execute(
            db.select(User).filter_by(email=email)).first()

        if not user:
            return {
                       'message': 'The email or password is wrong!'
                   }, 400
        else:
            user = user[0]  # Unpack the array.
        # END: Check email existance.

        # BEGIN: Check password hash.
        if check_password_hash(user.password, password):
            payload = {
                'user_id': user.id,
                'email': user.email,
                'aud': AUDIENCE_MOBILE,  # AUDIENCE_WEB
                'iss': ISSUER,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours=2)
            }
            token = jwt.encode(payload, SECRET_KEY)
            return {
                       'token': token
                   }, 200
        else:
            return {
                       'message': 'Wrong email or password!'
                   }, 400
        # END: Check password hash.


#########################
##### END: login #####

# Token Auth
SECRET_KEY = "WhatEverYouWant"
ISSUER = "myFlaskWebService"
AUDIENCE_MOBILE = "myMobileApp"

parser4email = reqparse.RequestParser()
parser4email.add_argument('token', type=str,
                          location='headers', required=True)

@api.route('/token')
class toke(Resource):
    @api.expect(parser4email)
    def post(self):
        args = parser4email.parse_args()
        token = args['token']
        payload = jwt.decode(
            token,
            SECRET_KEY,
            audience=AUDIENCE_MOBILE,
            issuer=ISSUER,
            algorithms=['HS256'],
            options={"require": ["aud", "iss", "iat", "exp"]}
        )
        if payload:
            return {
                "token": "token_value", "message": "Token Success! Cek Email Token!"
            }
        else:
            return {
                "message": "Token Gagal!"

            }

#######################


################################

if __name__ == '__main__':
    app.run(debug=True)