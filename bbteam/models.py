import hashlib
import urllib
from flask.ext.login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from bbteam import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)

    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get_by_username(username):
        return User.query.filter_by(username=username).first()

    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()

    def avatar(self, size=50):
        gravatar_url = "http://www.gravatar.com/avatar/" + hashlib.md5(self.email.lower()).hexdigest() + "?"
        gravatar_url += urllib.urlencode({'s': str(size)})
        return gravatar_url

    def __repr__(self):
        return "<User '{}'>".format(self.username)
