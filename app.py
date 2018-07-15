import getpass
import os

from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from crontab import CronTab

from db import db
from blacklist import BLACKLIST
from resources.user import (UserRegister, User, UserLogin,
                            TokenRefresh, UserLogout, Subscribe)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'mysql://admin:admin@localhost/weather_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
# enable blacklist feature
app.config['JWT_BLACKLIST_ENABLED'] = True
# allow blacklisting for access and refresh tokens
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
# could do app.config['JWT_SECRET_KEY']
app.secret_key = 'developer'
api = Api(app)


@app.before_first_request
def create_tables():
    db.create_all()


jwt = JWTManager(app)


@jwt.user_claims_loader
def add_claims_to_jwt(identity):

    if identity == 1:
        return {'is_admin': True}
    return {'is_admin': False}


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return decrypted_token['jti'] in BLACKLIST


@jwt.expired_token_loader
def expired_token_callback():
    return jsonify({
        'message': 'The token has expired.',
        'error': 'token_expired'
    }), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'message': 'Signature verification failed.',
        'error': 'invalid_token'
    }), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        "description": "Request does not contain an access token.",
        'error': 'authorization_required'
    }), 401


@jwt.needs_fresh_token_loader
def token_not_fresh_callback():
    return jsonify({
        "description": "The token is not fresh.",
        'error': 'fresh_token_required'
    }), 401


@jwt.revoked_token_loader
def revoked_token_callback():
    return jsonify({
        "description": "The token has been revoked.",
        'error': 'token_revoked'
    }), 401


api.add_resource(UserRegister, '/register')
api.add_resource(User, '/user/<int:row_id>')
api.add_resource(UserLogin, '/login')
api.add_resource(TokenRefresh, '/refresh')
api.add_resource(UserLogout, '/logout')
api.add_resource(Subscribe, '/subscribe/<int:row_id>')


def schedule_task():
    my_cron = CronTab(user=getpass.getuser())
    job = my_cron.new(command=os.path.abspath('weather.py'))
    job.minute.every(1)
    my_cron.write()


if __name__ == '__main__':
    db.init_app(app)
    schedule_task()
    app.run(debug=True)
