import os

from flask import Flask, jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from dotenv import load_dotenv

import models
from db import db
from blacklist import BLACKLIST

from resources.user import blp as UserBluePrint


def create_app():
    app = Flask(__name__)
    load_dotenv()
    app.config["DEBUG"] = True
    app.config["API_TITLE"] = "JWT "
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///data.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = True

    db.init_app(app)  # connect flask app with sqlalchemy

    Migrate(app, db)

    # Flask smorest extension around Flask
    api = Api(app)

    # JWT
    # generate using secrets str(secrets.SystemRandom().getrandbits(128)).
    app.config["JWT_SECRET_KEY"] = '115821006952800699779739990316390504861'
    jwt = JWTManager(app)

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return (
            jsonify(
                {
                    "message": "The token has expired.",
                    "error": "token_expired"
                }),
            401,
        )

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return (
            jsonify(
                {
                    "message": "Signature verification failed.",
                    "error": "invalid_token"
                }
            ),
            401,
        )

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return (
            jsonify(
                {
                    "message": "Request does not contain an access token.",
                    "error": "authorization_required",
                }
            ),
            401,
        )

    @jwt.additional_claims_loader
    def add_claims_to_jwt(identity):
        """
        Add extra claims to JWT
        TODO: Add claims based on data in the database
        :param identity:
        :return:
        """
        return {"is_admin": True} if identity == 1 else {"is_admin": False}

    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        return jwt_payload["jti"] in BLACKLIST

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return (
            jsonify(
                {"description": "The token has been revoked.", "error": "token_revoked"}
            ),
            401,
        )

    # Create database schemas at first request
    #with app.app_context():
    #    db.create_all()

    api.register_blueprint(UserBluePrint)

    return app


if __name__ == '__main__':
    app = create_app()
    app.run()

