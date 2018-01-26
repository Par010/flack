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
