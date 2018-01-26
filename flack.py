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
    users = User.query.filter_by(User.last_seen_at < timestamp() - 60, User.online == True).all() #check if the user has been offline for more than a min
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
                'self' : url_for('get_message', id=self.id),
                'user' : url_for('get_user', id=self.user_id)
            }

        }

    def render_markdown(self, source):
        #render markdown source to html with a tag whitelist
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i', 'strong']
        self.html = bleach.linkify(bleach.clean(
            markdown(source, output_format='html'),
            tags = allowed_tags, strip = True))


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
                soup = BeautifulSoup(rv.text, 'html5lib')   #parse the text into html5lib
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

@basic_auth.verify_password
def verify_password(nickname, password):
    #password verification callback
    if not nickname or not password:
        return False
    user = User.query.filter_by(nickname=nickname).first()
    if user is None or user.verify_password(password):
        return False
    user.ping()
    db.session.add(user)
    db.session.commit()
    g.current_user = user
    return True

@basic_auth.error_handler
def password_error():
    #return 401 error to the client
    # to avoid login prompts in the browser, use the "Bearer" realm.
    return (jsonify({'error': 'Authentication required'}),401,{'WWW-Authenticate' : 'Bearer realm = "Authentication Required"'})

@token_auth.verify_token
def verify_token(token):
    #token verification callback
    user = User.query.filter_by(token=token).first()
    if user is None:
        return False
    user.ping()
    db.session.add(user)
    db.session.commit()
    g.current_user = user
    return True

@token_auth.error_handler
def token_error():
    #return a 401 error to the client
    return (jsonify({'error':'Authentication required'}, 401, {'WWW-Authenticate' : 'Bearer realm = "Authentication required"'}))

@token_optional_auth.verify_token
def verify_optional_token(token):
    """Alternative token authentication that allows anonymous logins."""
    if token == "":
        #no token provided mark the logged in users as none and continue
        g.current_user = None
        return True
    #but if token was provided verify token
    return verify_token(token)

@app.before_first_request
def before_first_request():
    #start a background thread for users that leave
    def find_offline_users():
        while True:
            User.find_offline_users()
            db.session.remove()
            time.sleep(5)

    if not app.config['TESTING']:
        thread = threading.Thread(target=find_offline_users)
        thread.start()

@app.before_request
def before_request():
    #update request per second stats
    t = timestamp()
    while len(request_stats) > 0 and request_stats[0] < t - 15:
        del request_stats[0]
    request_stats.append(t)

@app.route('/')
def index():
    #serve client side application
    return render_template('index.html')

@app.route('/api/users', methods=['POST'])
def new_user():
    #Register a new user, this endpoint is publicly available
    user = User.create(request.get_json() or {})
    if User.query.filter_by(nickname=user.nickname).first() is not None:   #check if user exists
        abort(400)  #status code for bad request
    db.session.add(user)
    db.session.commit()
    r = jsonify(user.to_dict())
    r.status_code = 201    #status code for created
    r.headers['location'] = url_for('get_user', id = user.id)
    return r

@app.route('api/users', methods=['GET'])
def get_users():
    """Return list of users. endpoint is public but if the client has a token it should send it, indicationg that the user is online"""
    users = User.query.order_by(User.updated_at.asc(), User.nickname.asc())
    if request.args.get('online'):
        users = users.filter_by(online = (request.args.get('online') != '0'))
    if request.args.get('updated_since'):
        users = users.filter(
            User.updated_at > int(request.args.get('updated_since'))
        )
    return jasonify({'users' : [user.to_dict() for user in users.all()]})

@app.route('api/users/<id>', methods=['GET'])
@token_optional_auth.login_required
def get_user(id):
    """
    Return a user.
    This endpoint is publicly available, but if the client has a token it
    should send it, as that indicates to the server that the user is online."""
    return jasonify(User.query.get_or_404(id).to_dict())

@app.route('api/users/<id>', methods=['POST'])
@token.auth.login_required
def edit_user(id):
    """
    Modify an existing user.
    This endpoint is requires a valid user token.
    Note: users are only allowed to modify themselves.
    """
    user = User.query.get_or_404(id)
    if user != g.current_user:
        abort(403)
    user.from_dict(request.get_json() or {})
    db.session.add(user)
    db.session.commit()
    return '',204

@app.route('api/tokens', methods=['POST'])
@basic_auth.login_required
def new_token():
    """
    Request a user token.
    This endpoint is requires basic auth with nickname and password.
    """
    if g.current_user.token is None:
        g.current_user.generate_token():
        db.session.add(g.current_user)
        db.session.commit()
    return jsonify({'token' : g.current_user.token})

@app.route('api/tokens', methods=['DELETE'])
@token_auth.login_required
def revoke_token():
    """Revoke user token, this requires valid user token"""
    g.current_user.token = None
    db.session.add(g.current_user)
    db.session.commit()
    return "", 204

@app.route('api/messages', methods=['GET'])
@token_optional_auth.login_required
def get_messages():
    """
    Return list of messages.
    This endpoint is publicly available, but if the client has a token it
    should send it, as that indicates to the server that the user is online.
    """
    since = int(request.args.get('updated_since', '0'))
    day_ago = timestamp() - 24 * 60 * 60
    if since < day_ago:
        #do not return msgs from more than a day ago
        since = day_ago
    msgs = Message.query.filter(Message.updated_at > since).order_by(Message.updated_at)
    return jasonify({'messages' : [msg.to_dict for msg in msgs.all()]})

@app.route('api/messages/<id>', methods=['GET'])
@token_optional_auth.login_required
def get_messages(id):
    """
    Return a message.
    This endpoint is publicly available, but if the client has a token it
    should send it, as that indicates to the server that the user is online.
    """
    return jasonify(Message.query.get_or_404(id).to_dict)

@app.route('api/messages/<id>', methods=['PUT'])
@token_auth.login_required
def edit_message(id):
    """
    Modify an existing message.
    This endpoint is requires a valid user token.
    Note: users are only allowed to modify their own messages.
    """
    msg = Message.query.get_or_404(id)
    if msg.user != g.current_user:
        abort(403)    #status code for forbidden request
    msg.from_dict(request.get_json() or {})
    db.session.add(msg)
    db.session.commit()
    return '', 204    #status code for no content

@app.route('/stats', methods=['GET'])
def get_stats():
    return jasonify('requests_per_second' : len(request_stats) / 15)   #requests before 15 secs are deleted

if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', debug = True)
