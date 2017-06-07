import eventlet
eventlet.monkey_patch()

import pytest
import jwt

from application.services.api import http


class DummyService(object):
    name = 'dummy_service'

    @http('GET', '/myget', ('admin', 'write',))
    def do_get(self, request):
        return 'OK'


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


@pytest.fixture
def web_session(container_factory, web_config, web_session, secret_key):
    web_config['SECRET_KEY'] = secret_key
    container = container_factory(DummyService, web_config)
    container.start()

    return web_session


def test_decorator(web_session, admin_token, write_token, read_token):
    resp = web_session.get('/myget', headers={'Authorization': admin_token})
    assert resp.status_code == 200

    resp = web_session.get('/myget', headers={'Authorization': write_token})
    assert resp.status_code == 200

    resp = web_session.get('/myget', headers={'Authorization': read_token})
    assert resp.status_code == 403

    resp = web_session.get('/myget')
    assert resp.status_code == 401
