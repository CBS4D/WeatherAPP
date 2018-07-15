from flask_restful import Resource, reqparse
from werkzeug.security import safe_str_cmp
from flask_jwt_extended import (
    create_access_token,
    jwt_refresh_token_required,
    get_jwt_identity,
    jwt_required,
    get_raw_jwt,
    create_refresh_token,
    get_jwt_claims
)
from models.user import UserModel
# from models.subscibe import SubscribeModel
from blacklist import BLACKLIST

# bp = Blueprint('auth', __name__, prefix='/auth')

register_parser = reqparse.RequestParser()
register_parser.add_argument('username',
                             type=str,
                             required=True,
                             help="This field cannot be blank."
                             )
register_parser.add_argument('password',
                             type=str,
                             required=True,
                             help="This field cannot be blank."
                             )
register_parser.add_argument('organisation_name',
                             type=str,
                             required=True,
                             help="This field cannot be blank."
                             )
register_parser.add_argument('website_url',
                             type=str,
                             required=True,
                             help="This field cannot be blank."
                             )

login_parser = reqparse.RequestParser()
login_parser.add_argument('username',
                          type=str,
                          required=True,
                          help="This field cannot be blank."
                          )
login_parser.add_argument('password',
                          type=str,
                          required=True,
                          help="This field cannot be blank."
                          )

sub_parser = reqparse.RequestParser()
sub_parser.add_argument('subscribe',
                        type=bool,
                        required=True,
                        help="This field cannot be blank."
                        )


class UserRegister(Resource):
    def post(self):
        data = register_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {"message": "A user with that username already exists"}, 400

        user = UserModel(**data)
        user.save_to_db()

        return {"message": "User created successfully."}, 201


class User(Resource):

    @classmethod
    def get(cls, row_id):
        user = UserModel.find_by_id(row_id)
        if not user:
            return {'message': 'User Does Not Exist'}, 404
        return user.json(), 200

    @jwt_required
    def delete(self, row_id):
        claims = get_jwt_claims()
        if not claims['is_admin']:
            return {'message': 'Admin privilege required.'}, 401
        user = UserModel.find_by_id(row_id)
        if not user:
            return {'message': 'User Not Found'}, 404
        user.delete_from_db()
        return {'message': 'User deleted.'}, 200


class UserLogin(Resource):
    def post(self):
        data = login_parser.parse_args()

        user = UserModel.find_by_username(data['username'])

        if user and safe_str_cmp(user.password, data['password']):
            access_token = create_access_token(
                identity=user.row_id, fresh=True)
            # refresh_token = create_refresh_token(user.row_id)
            return {
                'access_token': access_token
                # 'refresh_token': refresh_token
            }, 200

        return {"message": "Invalid Credentials!"}, 401


class Subscribe(Resource):
    @jwt_required
    def put(self, row_id):
        data = sub_parser.parse_args()
        model = UserModel.find_by_id(row_id)
        if not model:
            return {'message': 'User Not Found'}, 404
        if data['subscribe'] != model.subscribe:
            model.subscribe = data['subscribe']
            model.update()
            return {'message': 'User Subscription updated!'}, 200
            # return {'weather', weather}
        return {'message': 'User is on same status'}, 200


class UserLogout(Resource):
    @jwt_required
    def post(self):
        # jti is "JWT ID", a unique identifier for a JWT.
        jti = get_raw_jwt()['jti']
        BLACKLIST.add(jti)
        return {"message": "Successfully logged out"}, 200


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        """
        Get a new access token without requiring username and
        password—only the 'refresh token' provided in the /login endpoint.

        Note that refreshed access tokens have a `fresh=False`,
        which means that the user may have not given us their
        username and password for potentially a long time
        (if the token has been refreshed many times over).
        """
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_token}, 200
