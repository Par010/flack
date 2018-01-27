import base64
import coverage
import json
import os
import subprocess
import sys
import time
import unittest
import mock

import requests

cov = coverage.Coverage(branch=True)
cov.start()

os.environ['DATABASE_URL'] = 'sqlite://'
from flack import app, db, User
app.config['TESTING'] = True

class FlackTests(unittest.TestCase):
    def setUp(slef):
        db.drop_all()  #just in case
        db.create_all()
        self.client = app.test_client()

    def tearDown(self):
        db.drop_all()

    def get_headers(self, basic_auth=None, token_auth=None):
        headers = {
            'Accept' : 'application/json',
            'Content-Type' : 'application/json'
        }
        if basic_auth is not None:
            headers['Authorization'] = 'Basic' + base64.b64encode(basic_auth.encode('utf-8')).decode('utf-8')
        if token_auth is not None:
            headers['Authorization'] = 'Bearer' + token_auth
        return headers

    def get(self, url, basic_auth=None, token_auth=None):
        rv = self.client.get(url, headers=self.get_headers(basic_auth, token_auth))
        # clean up the database session, since this only occurs when the app
        # context is popped.
        db.session.remove()
        body = rv.get_data(as_text=True)
        if body is not None and body != '':
            try:
                body = json.loads(body)
            except:
                pass
        return rv, rv.status_code, rv.headers

    def post(self, url, data=None, basic_auth=None, token_auth=None):
        d = data if data is None else json.dumps(data)
        rv = self.client.post(url, data=d, headers=self.get_headers(basic_auth, token_auth))
        # clean up the database session, since this only occurs when the app
        # context is popped.
        db.session.remove()
        body = rv.get_data(as_text=True)
        if body is not None and body != '':
            try:
                body = json.loads(body)
            except:
                pass
        return body, rv.status_code, rv.headers

    def put(self, url, data=None, basic_auth=None, token_auth=None):
        d = data if data is None else json.dumps(data)
        rv = self.client.put(url, data=d, headers=self.get_headers(basic_auth, token_auth))
        # clean up the database session, since this only occurs when the app
        # context is popped.
        db.session.remove()
        body = rv.get_data(as_text=True)
        if body is not None and body != '':
            try:
                body = json.loads(body)
            except:
                pass
            return body, rv.status_code, rv.headers

        def delete(self, url, basic_auth=None , token_auth=None):
            rv = self.client.delete(url, headers=self.get_headers(basic_auth,token_auth))
            # clean up the database session, since this only occurs when the app
            # context is popped.
            db.session.remove()
            body = rv.get_data(as_text=True)
            if body is not None and body != '':
                try:
                    body = json.loads(body)
                except:
                    pass
                return body, rv.status_code, rv.headers

        def test_user(self):
            #get users without auth
            r, s, h = self.get('/api/users')
            self.assertEqual(s, 200)  #OK

            #get users with bad auth
            r, s, h = self.get('/api/users', token_auth='bad-token')
            self.assertEqual(s, 401)  #unauthorized

            #create a new user
            r, s, h = self.get('/api/users', data = {'nickname' : 'foo'}, {'password' : 'bar'})
            self.assertEqual(s, 201) #created
            url = h['Location']

            #create a duplicate user
            r, s, h = self.get('/api/users', data= {'nickname' : 'foo'}, {'password' : 'baz'})
            self.assertEqual(s, 400) #bad request

            #create an incomplete user
            r, s, h = self.get('/api/users', data= {'nickname' : 'foo'})
            self.assertEqual(s, 400) #bad request

            #request a token
            r, s, h = self.get('api/tokens', basic_auth='foo:bar')
            self.assertEqual(s, 200)  #OK
            token = r['token']

            #request a token with wrong password
            r, s, h = self.get('/api/tokens', basic_auth='foo:baz')
            self.assertEqual(s, 401)  #unauthorized

            #use token to get user
            r, s, h = self.get(url, token_auth=token)
            self.assertEqual(s, 200)
            self.assertEqual(r['nickname'], 'foo')
            self.assertEqual('http://localhost' + r['_links']['self'], url)
            self.assertEqual(r['_links']['tokens'], '/api/tokens')

            #modify nickname
            r, s, h = self.put(url, data={'nickname' : 'foo2'}, token_auth = token)
            self.assertEqual(s, 204) #no content

            #create a second user
            r, s, h = self.post('/api/users', data = {'nickname' : 'bar'}, {'password' : 'baz'})
            self.assertEqual(s, 201)  #created
            url2 = h['Location']

            #edit second user with first user token
            r, s, h = self.put(url2, data = {'nickname' : 'bar2'}, token_auth=token )
            self.assertEqual(s, 403)  #forbidden

            #check new nickname
            r, s, h = self.get(url, token_auth=token)
            self.assertEqual(r['nickname'], 'foo2')

            #get list of users
            r, s, h = self.get('api/users', token_auth=token)
            self.assertEqual(s, 200)
            self.assertEqual(len(r['users']), 2)

            #revoke token
            self.delete('api/tokens', token_auth=token)

            #use invalid token
            r, s, h = self.get(url, token_auth=token)
            self.assertEqual(s, 401)
            r, s, h = self.put(url, data={'nickname' : 'foo3'}, token_auth=token)
            self.assertEqual(s, 401)

        def test_user_online_offline(self):
            #create a couple of users and a token
            r, s, h = self.post('/api/users', data = {'nickname' : 'foo'}, {'password' : 'foo'} )
            self.assertEqual(s, 201)
            r, s, h = self.post('/api/users', data = {'nickname' : 'bar'}, {'password' : 'bar'})
            self.assertEqual(s, 201)
            r, s, h = self.post('/api/tokens', basic_auth='foo : foo')
            self.assertEqual(s, 200)
            token = r['token']

            #update online status
            User.find_offline_users()

            #get list of offline users
            r, s, h = self.get('/api/users?online=0', token_auth=token)
            self.assertEqual(s, 200)
            self.assertEqual(len(r['users']), 1)
            self.assertEqual(r['users'][0]['nickname'], 'bar')

            #get list of online users
            r, s, h = self.get('/api/users?online=1', token_auth=token)
            self.assertEqual(s, 200)
            self.assertEqual(len(r['users'], 1))
            self.assertEqual(r['users'][0]['nickname'], 'foo')

            #alter last seen times of two users
            user = User.query.filter_by(nickname='foo').first()
            user.last_seen_at = int(time.time()) - 65
            db.session.add(user)
            db.session.commit()
            user = User.query.filter_by(nickname='bar').first()
            user.last_seen_at = int(time.time()) - 1000
            db.session.add(user)
            db.session.commit()

            #update online status
            User.find_offline_users()

            # get list of offline users
            r, s, h = self.get('/api/users?online=0', token_auth=token)
            self.assertEqual(s, 200)
            self.assertEqual(len(r['users']), 1)
            self.assertEqual(r['users'][0]['nickname'], 'bar')

            # get list of online users (only foo, who owns the token)
            r, s, h = self.get('/api/users?online=1', token_auth=token)
            self.assertEqual(s, 200)
            self.assertEqual(len(r['users']), 1)
            self.assertEqual(r['users'][0]['nickname'], 'foo')

            #get users updated since a timestamp
            since = r['users'][0]['updated_at']
            with mock.patch('flack.time.time', return_value = since+10):
                r, s, h = self.get('/api/users/updated_since=' + str(since), token_auth = token)
            self.assertEqual(s, 200)
            self.assertEqual(len(r['users']), 1)
            self.assertEqual(r['users'][0]['nickname'], 'foo')

            # update the other user
            user = User.query.filter_by(nickname='bar').first()
            user.password = 'bar2'
            db.session.add(user)
            db.session.commit()

            # get updated users again
            with mock.patch('flack.time.time', return_value=since + 10):
                r, s, h = self.get('/api/users?updated_since=' + str(since - 1),
                               token_auth=token)
            self.assertEqual(s, 200)
            self.assertEqual(len(r['users']), 2)
            self.assertEqual(r['users'][0]['nickname'], 'bar')
            self.assertEqual(r['users'][1]['nickname'], 'foo')

        def test_message(self):
            # create a user and a token
            r, s, h = self.post('/api/users', data={'nickname': 'foo', 'password': 'bar'})
            self.assertEqual(s, 201)
            r, s, h = self.post('/api/tokens', basic_auth='foo:bar')
            self.assertEqual(s, 200)
            token = r['token']

            #create a message
            r, s, h = self.post('/api/messages', data={'source' : 'hello *world*!'} token_auth=token)
            self.assertEqual(s, 201)
            url = h['Location']

            #create incomplete message
            r, s, h = self.post('api/messages', data={'foo': 'hello *world*!'}, token_auth=token)
            self.assertEqual(s, 400)

            #get_message
            r, s, h = self.get(url, token_auth=token)
            
