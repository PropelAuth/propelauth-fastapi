from datetime import timedelta

from tests.auth_helpers import create_access_token, random_user_id
from tests.conftest import HTTP_BASE_AUTH_URL


def test_require_user_without_auth(require_user_route, client, rsa_keys):
    response = client.get(require_user_route)
    assert response.status_code == 401


def test_require_user_with_auth(require_user_route, client, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)
    response = client.get(require_user_route, headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.text == user_id


def test_require_user_with_bad_header(require_user_route, client, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)
    response = client.get(require_user_route, headers={"Authorization": "token " + access_token})
    assert response.status_code == 401


def test_require_user_with_wrong_token(require_user_route, client, rsa_keys):
    response = client.get(require_user_route, headers={"Authorization": "Bearer whatisthis"})
    assert response.status_code == 401


def test_require_user_with_expired_token(require_user_route, client, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem, expires_in=timedelta(minutes=-1))
    response = client.get(require_user_route, headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 401


def test_require_user_with_bad_issuer(require_user_route, client, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem, issuer=HTTP_BASE_AUTH_URL)
    response = client.get(require_user_route, headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 401
