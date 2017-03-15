import eventlet
eventlet.monkey_patch()

import json

import pytest
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import BaseResponse, Request
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden
import jwt

from application.services.api import HttpAuthenticatedRequestHandler
    

@pytest.fixture
def admin_token(secret_key):

    payload = {'sub': 'my_user', 'role': 'admin'}

    tok = jwt.encode(payload, secret_key, algorithm='HS256')
    
    yield tok.decode('unicode_escape')
    

@pytest.fixture
def read_token(secret_key):

    payload = {'sub': 'my_user', 'role': 'read'}

    tok = jwt.encode(payload, secret_key, algorithm='HS256')
    
    yield tok.decode('unicode_escape')
    

@pytest.fixture
def write_token(secret_key):

    payload = {'sub': 'my_user', 'role': 'write'}

    tok = jwt.encode(payload, secret_key, algorithm='HS256')
    
    yield tok.decode('unicode_escape')    


def test_decorator(admin_token, write_token, read_token):
    auth_http = HttpAuthenticatedRequestHandler('POST', '/api/v1/command/twitter/add_user')

    builder = EnvironBuilder(method='POST', data=json.dumps({'user_id': 'JulienBernard70'}))
    env = builder.get_environ()
    
    req = Request(env)
    
    with pytest.raises(Unauthorized):
        auth_http.handle_request(req)
        
    builder = EnvironBuilder(method='POST', data=json.dumps({'user_id': 'JulienBernard70'}),
        headers={'Authorization': read_token})
    env = builder.get_environ()
    
    req = Request(env)
    
    with pytest.raises(Unauthorized):
        auth_http.handle_request(req)
    
    
    
    
    