import base64
import io
import json
import os
import urllib
import urllib.request

import jose.jwt
from oauthenticator.generic import GenericOAuthenticator
from tornado import gen
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from traitlets import Unicode, Dict, observe


class KeyCloakAuthenticator(GenericOAuthenticator):
    # There is only one authenticator instance

    admin_role = Unicode(
        config=True,
        help="Keycloak client role to grant admin access."
    )

    oidc_config_url = Unicode(
        os.environ.get('OIDC_CONFIG_URL', ''),
        config=True,
        help="Well-Known openid configuration url"
    )

    oidc_config = Dict(
        config=False,
        help="OIDC config loaded from oidc_config_url"
    )

    oidc_issuer = Unicode(
        os.environ.get('OIDC_ISSUER', ''),
        config=False,
        help="OIDC Issuer. Used to validate tokens."
    )

    jwks = Dict(
        config=False,
        help="JWKS (key set) to validate OIDC tokens (derived from oidc_config)"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # initial load of oidc config
        self._load_oidc_config()

    def _load_oidc_config(self):
        with urllib.request.urlopen(self.oidc_config_url) as resp:
            self.oidc_config = json.load(
                io.TextIOWrapper(resp, 'utf-8', 'replace')
            )

    @observe('oidc_config')
    def _oidc_config_changed(self, change):
        # change['new'], ['old']
        self.oidc_issuer = self.oidc_config.get('issuer', '')
        self.userdata_url = self.oidc_config.get('userinfo_endpoint', '')
        self.token_url = self.oidc_config.get('token_endpoint', '')
        self.login_handler._OAUTH_AUTHORIZE_URL = self.oidc_config.get('authorization_endpoint', '')
        self.login_handler._OAUTH_ACCESS_TOKEN_URL = self.oidc_config.get('token_endpoint', '')
        with urllib.request.urlopen(self.oidc_config['jwks_uri']) as resp:
            self.jwks = json.load(io.TextIOWrapper(resp, 'utf-8', 'replace'))

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        super().pre_spawn_start(user, spawner)

        auth_state = yield user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            return

        # spawner would have self.user, but there is no easy way to get
        # auth_state in spawner, as it is a coroutine, and everywhere
        # were we would need it it is either hard to inject env variables
        # or we can't call a coroutine.
        spawner.oauth_user = auth_state.get('oauth_user', {})

    def decode_jwt_token(self, token):
        return jose.jwt.decode(
            token, self.jwks,
            audience=self.client_id,
            issuer=self.oidc_issuer,
            # wo don't have at_hash in id_token, so we can't verify access_token here
            # access_token=access_token
        )

    def get_user_for_token(self, access_token):
        # accepts access_token and returns user name
        token = self.decode_jwt_token(access_token)
        return token.get(self.username_key, None)

    @gen.coroutine
    def authenticate(self, handler, data=None):
        http_client = AsyncHTTPClient()
        # short circuit if we have a token in data:
        # see https://github.com/jupyterhub/jupyterhub/pull/1840
        if data and 'token' in data:
            return self.get_user_for_token(data['token'])

        # trade authorization code for tokens
        code = handler.get_argument("code")
        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )
        params.update(self.extra_params)

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic {}".format(b64key.decode("utf8"))
        }
        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=urllib.parse.urlencode(params)  # Body is required for a POST...
        )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        # extract tokens
        access_token = resp_json['access_token']
        # expires_in: 300 ... access_token
        refresh_token = resp_json['refresh_token']
        # refresh_expires_in: 1800 ... refresh_token
        id_token = resp_json['id_token']
        scope = (resp_json.get('scope', '')).split(' ')

        # verify id_token
        id_token = self.decode_jwt_token(id_token)
        if not id_token.get(self.username_key):
            self.log.error("OAuth user contains no key %s: %s", self.username_key, id_token)
            return

        # verify and decode access token
        atok = self.decode_jwt_token(access_token)
        # get client roles from access token
        oidc_roles = atok.get('resource_access', {}).get(self.client_id, {}).get('roles', [])

        self.log.info('User {} is admin: {}'.format(id_token['name'], self.admin_role in oidc_roles))

        return {
            # TODO: do I want a decoded access token? ... e.g.
            'name': id_token.get(self.username_key),
            'admin': self.admin_role in oidc_roles,
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                # 'id_token': id_token,
                'oauth_user': id_token,
                'oauth_roles': oidc_roles,
                'scope': scope,
            }
        }
