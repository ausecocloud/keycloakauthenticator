import contextlib
import json
from unittest.mock import patch

from jose import jwt
import pkg_resources
from pytest import fixture, mark

from ..auth import KeyCloakAuthenticator

from .mocks import setup_oauth_mock


def user_model(username, oidc_config, audience='generic_horse'):
    """Return a user model"""
    return {
        'iss': oidc_config['issuer'],
        'aud': audience,
        'sub': username,

        'username': username,
        'scope': 'basic',
        'resource_access': {
            'generic_horse': {
                'roles': ['user'],
            },
        },
    }


def Authenticator():
    return KeyCloakAuthenticator(
        client_id='generic_horse',
        oidc_config_url='https://generic.horse/.well-known/oidc-configuration',
    )


@fixture
def oidc_config():

    @contextlib.contextmanager
    def oidc_doc(url):
        # called twice ... config and jwks
        if url == 'https://generic.horse/.well-known/oidc-configuration':
            yield pkg_resources.resource_stream(__name__, 'oidc_config.json')
        if url == 'https://generic.horse/certs':
            yield pkg_resources.resource_stream(__name__, 'jwks.json')

    with patch('urllib.request.urlopen', oidc_doc):
        yield


@fixture
def keycloak_client(client, oidc_config):
    setup_oauth_mock(
        client,
        host='generic.horse',
        access_token_path='/token',
        user_path='/userinfo',
    )
    return client


@mark.gen_test
def test_keycloak_audience(keycloak_client):
    authenticator = Authenticator()
    handler = keycloak_client.handler_for_user(
        user_model('wash', keycloak_client.oidc_config)
    )
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['admin', 'auth_state', 'name']
    assert user_info['name'] == 'wash'
    assert user_info['admin'] is False
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'oauth_user' in auth_state
    assert 'refresh_token' in auth_state
    assert 'scope' in auth_state


@mark.gen_test
def test_keycloak_roles(keycloak_client):
    authenticator = Authenticator()
    authenticator.required_roles = {'user'}
    handler = keycloak_client.handler_for_user(
        user_model('wash', keycloak_client.oidc_config)
    )
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['admin', 'auth_state', 'name']
    assert user_info['name'] == 'wash'
    assert user_info['admin'] is False
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'oauth_user' in auth_state
    assert 'refresh_token' in auth_state
    assert 'scope' in auth_state


@mark.gen_test
def test_keycloak_roles_aud(keycloak_client):
    authenticator = Authenticator()
    authenticator.required_roles = {'user'}
    handler = keycloak_client.handler_for_user(
        user_model(
            'wash', keycloak_client.oidc_config,
            audience='specific_horse'
        )
    )
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['admin', 'auth_state', 'name']
    assert user_info['name'] == 'wash'
    assert user_info['admin'] is False
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'oauth_user' in auth_state
    assert 'refresh_token' in auth_state
    assert 'scope' in auth_state


@mark.gen_test
def test_keycloak_is_admin(keycloak_client):
    authenticator = Authenticator()
    authenticator.admin_role = 'user'
    handler = keycloak_client.handler_for_user(
        user_model('wash', keycloak_client.oidc_config)
    )
    user_info = yield authenticator.authenticate(handler)
    assert sorted(user_info) == ['admin', 'auth_state', 'name']
    assert user_info['name'] == 'wash'
    assert user_info['admin'] is True
    auth_state = user_info['auth_state']
    assert 'access_token' in auth_state
    assert 'oauth_user' in auth_state
    assert 'refresh_token' in auth_state
    assert 'scope' in auth_state


@mark.gen_test
def test_keycloak_audience_fail(keycloak_client):
    authenticator = Authenticator()
    handler = keycloak_client.handler_for_user(
        user_model(
            'wash', keycloak_client.oidc_config,
            audience='specific_horse'
        )
    )
    user_info = yield authenticator.authenticate(handler)
    assert user_info is None


@mark.gen_test
def test_keycloak_roles_fail(keycloak_client):
    authenticator = Authenticator()
    authenticator.required_roles = {'nogroup'}
    handler = keycloak_client.handler_for_user(
        user_model('wash', keycloak_client.oidc_config)
    )
    user_info = yield authenticator.authenticate(handler)
    assert user_info is None


@mark.gen_test
def test_keycloak_token(keycloak_client):
    authenticator = Authenticator()
    jwk = json.load(pkg_resources.resource_stream(__name__, 'jwks.json'))['keys'][0]
    token = jwt.encode(
        user_model('wash', keycloak_client.oidc_config),
        jwk, algorithm=jwk['alg'],
    )
    user_name = yield authenticator.authenticate(None, data={'token': token})
    assert user_name == 'wash'

@mark.gen_test
def test_keycloak_token_roles(keycloak_client):
    authenticator = Authenticator()
    authenticator.required_roles = {'user'}
    jwk = json.load(pkg_resources.resource_stream(__name__, 'jwks.json'))['keys'][0]
    token = jwt.encode(
        user_model('wash', keycloak_client.oidc_config),
        jwk, algorithm=jwk['alg'],
    )
    user_name = yield authenticator.authenticate(None, data={'token': token})
    assert user_name == 'wash'

@mark.gen_test
def test_keycloak_token_fail(keycloak_client):
    authenticator = Authenticator()
    jwk = json.load(pkg_resources.resource_stream(__name__, 'jwks.json'))['keys'][0]
    token = jwt.encode(
        user_model('wash', keycloak_client.oidc_config, audience='other'),
        jwk, algorithm=jwk['alg'],
    )
    user_name = yield authenticator.authenticate(None, data={'token': token})
    assert user_name is None


@mark.gen_test
def test_keycloak_token_role_fail(keycloak_client):
    authenticator = Authenticator()
    authenticator.required_roles = {'other'}
    jwk = json.load(pkg_resources.resource_stream(__name__, 'jwks.json'))['keys'][0]
    token = jwt.encode(
        user_model('wash', keycloak_client.oidc_config),
        jwk, algorithm=jwk['alg'],
    )
    user_name = yield authenticator.authenticate(None, data={'token': token})
    assert user_name is None
