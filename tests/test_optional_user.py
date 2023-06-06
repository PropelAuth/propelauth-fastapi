from datetime import timedelta

from tests.auth_helpers import create_access_token, random_user_id
from tests.conftest import HTTP_BASE_AUTH_URL


def test_optional_user_without_auth(optional_user_route, client, rsa_keys):
    response = client.get(optional_user_route)
    assert response.status_code == 200
    assert response.text == "none"


def test_optional_user_with_auth(optional_user_route, client, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)
    response = client.get(optional_user_route, headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.text == user_id


def test_optional_user_with_bad_header(optional_user_route, client, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)
    response = client.get(optional_user_route, headers={"Authorization": "token " + access_token})
    assert response.status_code == 200
    assert response.text == "none"


def test_optional_user_with_wrong_token(optional_user_route, client, rsa_keys):
    response = client.get(optional_user_route, headers={"Authorization": "Bearer whatisthis"})
    assert response.status_code == 200
    assert response.text == "none"


def test_optional_user_with_expired_token(optional_user_route, client, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem, expires_in=timedelta(minutes=-5))
    response = client.get(optional_user_route, headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.text == "none"


def test_optional_user_with_bad_issuer(optional_user_route, client, rsa_keys):
    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem, issuer=HTTP_BASE_AUTH_URL)
    response = client.get(optional_user_route, headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.text == "none"
