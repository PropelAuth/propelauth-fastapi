import pytest

from tests.conftest import mock_api_and_init_auth, BASE_AUTH_URL, HTTP_BASE_AUTH_URL


def test_init(rsa_keys):
    mock_api_and_init_auth(BASE_AUTH_URL, 200, {
        "verifier_key_pem": rsa_keys.public_pem
    })


def test_init_with_slash(rsa_keys):
    mock_api_and_init_auth(BASE_AUTH_URL + "/", 200, {
        "verifier_key_pem": rsa_keys.public_pem
    })


def test_init_failure_raises():
    with pytest.raises(ValueError):
        mock_api_and_init_auth(BASE_AUTH_URL, 400, {})
    with pytest.raises(ValueError):
        mock_api_and_init_auth(BASE_AUTH_URL, 401, {})
    with pytest.raises(ValueError):
        mock_api_and_init_auth(BASE_AUTH_URL, 404, {})
    with pytest.raises(RuntimeError):
        mock_api_and_init_auth(BASE_AUTH_URL, 503, {})


