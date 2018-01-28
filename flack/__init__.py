import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap

from config import config

#flask extensions

db = SQLAlchemy()
bootstrap = Bootstrap()

# Import models so that they are registered with SQLAlchemy
from . import models

def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLACK_CONFIG', 'development')
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    #initialize flask extensions
    db.init_app(app)
    bootstrap.init_app(app)

    #register web application routes
    from .flack import main as main_blueprint
    app.register_blueprint(main_blueprint)

    #register API routes
    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    return app
