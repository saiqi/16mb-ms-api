import eventlet
eventlet.monkey_patch()

import pytest


def pytest_addoption(parser):
    parser.addoption('--test-secret-key', action='store', dest='TEST_SECRET_KEY')


@pytest.fixture
def secret_key(request):
    return request.config.getoption("TEST_SECRET_KEY")