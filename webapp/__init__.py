import logging
from logging.handlers import RotatingFileHandler
import os
from flask import Flask
from config import VarConfig
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bootstrap import Bootstrap


app = Flask(__name__)
app.config.from_object(VarConfig)
wappdb = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'
bootstrap = Bootstrap(app)
if app.config['LOG_TO_STDOUT']:
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    app.logger.addHandler(stream_handler)
else:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/heraldweb.log',
                                       maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Started')


from webapp import routes, models, errors
