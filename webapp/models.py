from webapp import wappdb
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from webapp import login
from time import time
import jwt
from webapp import app
from sqlalchemy.sql.expression import func
from Crypto.Cipher import AES
import requests


def encript_id(id_txt):
    n = 16 - len(str(id_txt))
    string_val = "".join(" " for i in range(n)) + str(id_txt)
    encryption_suite = AES.new(app.config['SECRET_KEY'].encode("ISO-8859-1"), AES.MODE_CBC,
                               iv=app.config['SECRET_IV'].encode("ISO-8859-1"))
    cipher_text = encryption_suite.encrypt(string_val.encode("ISO-8859-1"))
    return cipher_text.decode("ISO-8859-1")


class Service(wappdb.Model):
    id = wappdb.Column(wappdb.Integer, primary_key=True)
    stopped = wappdb.Column(wappdb.Boolean)
    in_use = wappdb.Column(wappdb.Boolean)


class Since(wappdb.Model):
    rule_id = wappdb.Column(wappdb.Integer, primary_key=True)
    idsince = wappdb.Column(wappdb.String, primary_key=True)


class Usedata(wappdb.Model):
    id = wappdb.Column(wappdb.String, primary_key=True)
    rule_id = wappdb.Column(wappdb.Integer)
    stamp = wappdb.Column(wappdb.String)
    trigger_text = wappdb.Column(wappdb.String)


class Rules(wappdb.Model):
    id = wappdb.Column(wappdb.Integer, primary_key=True)
    id_user = wappdb.Column(wappdb.Integer)
    handle = wappdb.Column(wappdb.String)
    lookfor = wappdb.Column(wappdb.String)
    discrobot = wappdb.Column(wappdb.String)
    media = wappdb.Column(wappdb.String)
    evrone = wappdb.Column(wappdb.Boolean)

    def enc_id(self):
        return encript_id(self.id)

    def new_id(self):
        mx = wappdb.session.query(func.max(Rules.id)).one()
        if mx[0] is not None:
            self.id = mx[0] + 1
        else:
            self.id = 1

    def hook_name(self):
        url = self.discrobot
        r = requests.get(url)
        return r.json()['name']


class User(UserMixin, wappdb.Model):
    id = wappdb.Column(wappdb.Integer, primary_key=True)
    username = wappdb.Column(wappdb.String(64), index=True, unique=True)
    email = wappdb.Column(wappdb.String(120), index=True, unique=True)
    password_hash = wappdb.Column(wappdb.String(128))
    level = wappdb.Column(wappdb.Integer)

    def enc_id(self):
        return encript_id(self.id)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    def new_id(self):
        mx = wappdb.session.query(func.max(User.id)).one()
        if mx[0] is not None:
            self.id = mx[0] + 1
        else:
            self.id = 1
        self.level = 1

    @staticmethod
    def verify_reset_password_token(token):
        try:
            idtkn = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['restablecer_password']
        except jwt.ExpiredSignatureError:
            return 'Expired Signature. Try to login again.'
        except jwt.InvalidTokenError:
            return 'Invalid Token. Try to login again.'
        return User.query.get(idtkn)


@login.user_loader
def load_user(idusr):
    return User.query.get(int(idusr))
