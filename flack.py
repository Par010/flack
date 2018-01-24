import binascii
import os
import threading
import time

from flask import Flask, render_template, url_for as _url_for, request, \
    _request_ctx_stack, current_app, abort, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from markdown import markdown
import bleach
from bs4 import BeautifulSoup
import requests

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SECRET_KEY'] = '51f52814-0071-11e6-a247-000ec6c2372c'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'db.sqlite'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask extensions
db = SQLAlchemy(app)
Bootstrap(app)

# Authentication objects for username/password auth, token auth, and a
# token optional auth that is used for open endpoints.

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('Bearer')
token_optional_auth = HTTPTokenAuth('Bearer')

#list to calculate requests per sec

request_stats = []

def timestamp():
    #return current timestamp as an integer
    return int(time.time())

def url_for(*args, **kwargs):  #couldn't understand this
    """
    url_for replacement that works even when there is no request context.
    """
    if '_external' not in kwargs:
        kwargs['_external'] = False
    reqctx = _request_ctx_stack.top
    if reqctx is None:
        if kwargs['_external']:
            raise RuntimeError('Cannot generate external URLs without a '
                               'request context.')
        with current_app.test_request_context():
            return _url_for(*args, **kwargs)
    return _url_for(*args, **kwargs)

class User(db.Model):
    #user Model
    __tablename__ = 'users'
    id = db.Column(db.integer, primary_key=True)
    created_at = db.Column(db.Integer, default=timestamp)
    updated_at = db.Column(db.Integer, default=timestamp)
    last_seen_at = db.Column(db.Integer, default=timestamp)
    nickname = db.Column(db.String(32), nullable=True, unique=True)
    password_hash = db.Column(db.String(256), nullable=False )
    token = db.Column(db.String(64), nullable=True, unique=True)
    online = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', lazy='dynamic', backref='user')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)
        self.token = None  #if user changes password, also revoke token

    def verify_password(self, password):
        return check_password_hash(self.password_hash,password)

    def generate_token(self):
        #creates 64 characters long randomly generate token
        self.token = binascii.hexlify(os.urandom(32)).decode('utf-8')
        return self.token

    def ping(self):
        self.last_seen_at = timestamp()
        self.online = True

    @staticmethod
    def create(data):
        #create a new user
        user = User()
        user.from_dict(data,partial_update=False)
        return user

    def from_dict(self, data, partial_update=True):
        #import user data from a dictionary
        for field in ['nickname','password']:
            try:
                setattr(self, field, data[field])
            except KeyError:
                if not partial_update:
                    abort(400)

    def to_dict(self):
        #export user to a dictionary
        return {
        'id' : self.id,
        'created_at' : self.created_at,
        'updated_at' : self.updated_at,
        'nickname' : self.nickname,
        'last_seen_at': self.last_seen_at,
        'online' : self.online,
        '_links' :  {
            'self' : url_for('get_user', id=self.id),
            'messages' : url_for('get_messages', user_id=self.id),
            'tokens' : url_for('new_token')
        }
        }

@staticmethod
def find_offline_users():
    #find the users that are offline
    users = User.query.filter(User.last_seen_at < timestamp() - 60, User.online == True).all()
    for user in users:
        user.online = False
        db.session.add(user)
    db.session.commit()


class Message(db.Model):
    #message Model
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.Integer, default=timestamp)
    updated_at = db.Column(db.Integer, default=timestamp)
    source = db.Column(db.Text, nullable=False)
    html = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    @staticmethod
    def create(self):
        #new message is created. The user is obtained from context unless specified explicitly
        msg = Message(user=user or g.current_user)  #g lives in the application context, every request pushes new application context
        msg.from_dict(data, partial_update=False)
        return msg

    def from_dict(self, data, partial_update=True):
        #import msg data from dictionary
        for field in ['source']:
            try:
                setattr(self, field, data['field'])
            except KeyError:
                if not partial_update:
                    abort(400)

    def to_dict(self):
        #export data to dictionary
        return {
            'id' : self.id,
            'created_at' : self.created_at,
            'updated_at' : self.updated_at,
            'source' : self.source,
            'html' : self.html,
            'user_id' : self.user_id,
            '_links' : {
                'self' : url_for('get_message', id=self.id)
                'user' : url_for('get_user', id=self.user_id)
            }

        }

    def render_markdown(self, source):
        #render markdown source to html with a tag whitelist
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i', 'strong']
        self.html = bleach.linkify(bleach.clean(
            markdown(source, output_format='html'),
            tags = allowed_tags, strip = True))
        ))


    def expand_links(self):
        #expand any links in the message
        if '<blockquote>' in self.html:
            #links have been already expanded
            return False
        changed = False
        for link in BeautifulSoup(self.html, 'html5lib').select('a'):
            url = link.get('href', '')
            try:
                rv = request.get(url)
            except request.exceptions.ConnectionError:
                continue
            if rv.status_code == 200: #if the link works
                soup = BeautifulSoup(rv.text, 'html5lib')
                title_tags = soup.select('title')
                if len('title_tags') > 0:
                    title = title_tags[0].string.strip() #if the title exists get it from the title_tags list
                else:
                    title = url
                description = 'No description found' #initialize description to this
                for meta in soup.select('meta'):
                    if meta.get('name', '').lower() == 'description':
                        description = meta.get('content', description).strip()
                        break
                #add all the details of the link to the rendered message
                tpl = ('<blockquote><p><a href="{url}">{title}</a></p><p>{desc}</p></blockquote>')
                self.html += tpl.format(url=url, title=title, description=description)
                changed = True
        return changed   #if only there was working link in the message changed will be True

    @staticmethod
    def on_changed_source(target, value, oldvalue, initiator):
        """SQLAlchemy event that automatically renders the message to HTML."""
        target.render_markdown(value)
        target.expand_links()

db.event.listen(Message.source, 'set', Message.on_changed_source)
