from collections import namedtuple
from typing import Optional

import pytest
import requests_mock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from starlette.responses import PlainTextResponse

from propelauth_fastapi import init_auth, User

TestRsaKeys = namedtuple("TestRsaKeys", ["public_pem", "private_pem"])

BASE_AUTH_URL = "https://test.propelauth.com"
HTTP_BASE_AUTH_URL = "http://test.propelauth.com"


@pytest.fixture(scope='function')
def app():
    app = FastAPI()
    return app


@pytest.fixture(scope='function')
def client(app):
    return TestClient(app)


@pytest.fixture(scope='function')
def rsa_keys():
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return TestRsaKeys(public_pem=public_key_pem, private_pem=private_key_pem)


@pytest.fixture(scope='function')
def auth(rsa_keys):
    return mock_api_and_init_auth(BASE_AUTH_URL, 200, {
        "verifier_key_pem": rsa_keys.public_pem
    })


@pytest.fixture(scope='function')
def require_user_route(app, auth):
    route_name = "/require_user"

    @app.get(route_name)
    async def read_main(current_user: User = Depends(auth.require_user)):
        return PlainTextResponse(current_user.user_id)

    return route_name


@pytest.fixture(scope='function')
def optional_user_route(app, auth):
    route_name = "/optional_user"

    @app.get(route_name)
    async def read_main(current_user: Optional[User] = Depends(auth.optional_user)):
        if current_user is not None:
            return PlainTextResponse(current_user.user_id)
        else:
            return PlainTextResponse("none")

    return route_name


def mock_api_and_init_auth(auth_url, status_code, json):
    with requests_mock.Mocker() as m:
        api_key = "api_key"
        m.get(BASE_AUTH_URL + "/api/v1/token_verification_metadata",
              request_headers={'Authorization': 'Bearer ' + api_key},
              json=json,
              status_code=status_code)
        return init_auth(auth_url, api_key)
