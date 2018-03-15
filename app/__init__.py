
from flask import Flask                     #import flask module
from app.views.home import home
from app.views.wallet import wallet
from app.views.login import login

def create_app():
    app = Flask(__name__)

    app.config.update(
        DEBUG = True,
        SECRET_KEY = 'secret_xxx'
    )

    app.register_blueprint(home)
    app.register_blueprint(login)
    app.register_blueprint(wallet)

    return app
