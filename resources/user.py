from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token, get_jwt, jwt_required, \
    create_refresh_token, get_jwt_identity
from sqlalchemy import or_
from passlib.hash import pbkdf2_sha256

from blacklist import BLACKLIST
from db import db
from models.user import UserModel
from schema import UserSchema, UserRegistrationSchema


blp = Blueprint("Users", "users", description="Operations on users")


@blp.route("/register")
class UserRegistration(MethodView):
    @blp.arguments(UserRegistrationSchema)
    def post(self, user_data):
        """
        Register new user to the system
        :param user_data: user data consisting of name, password and email
        :return: str
        """
        if UserModel.query.filter(or_(
                UserModel.name == user_data['name'], UserModel.email == user_data['email'])
                                  ).first():
            abort(409, "Username or email already exist.")
        user = UserModel(
            name=user_data['name'],
            password=pbkdf2_sha256.hash(user_data['password']), # hash the password
            email=user_data['email']
        )
        db.session.add(user)
        db.session.commit()

        return {"message": "User successfully created."}, 201


@blp.route("/login")
class Login(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        """
        :return:
        """
        user = UserModel.query.filter(UserModel.name == user_data['name']).first()

        if user and pbkdf2_sha256.verify(user_data['password'], user.password):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {"access_token" : access_token, "refresh_token" : refresh_token}, 200

        abort(401, message="Invalid credentials.")


@blp.route("/logout")
class Logout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        BLACKLIST.add(jti)
        return {"message": "Successfully logged out"}, 200


@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        user_id = get_jwt_identity()
        new_token = create_access_token(identity=user_id, fresh=False)
        jti = get_jwt()["jti"]
        BLACKLIST.add(jti)
        return {"access_token": new_token}, 200


@blp.route("/user/<int:user_id>")
class User(MethodView):
    """
    Get a  User, Deleting User for testing purposes.
    """
    @blp.response(200, UserSchema)
    def get(self, user_id):
        """
        Get a user
        :param user_id: user id
        :return: user
        """
        user = UserModel.query.get_or_404(user_id)
        return user

    @jwt_required
    def delete(self, user_id):
        """
        Delete a user
        :param user_id: user id
        :return: str
        """
        jwt = get_jwt()
        if not jwt.get("is_admin"):
            abort(401, message="Admin privilege required.")

        user = UserModel.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {"message": "User deleted."}, 200
