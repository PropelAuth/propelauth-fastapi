from datetime import timedelta
from uuid import uuid4

from fastapi import Depends
from starlette.responses import PlainTextResponse

from tests.auth_helpers import create_access_token, orgs_to_org_id_map, random_org, random_user_id
from tests.conftest import HTTP_BASE_AUTH_URL

ROUTE_NAME = "/require_org_member_route"


def test_require_org_member_without_auth(app, auth, client, rsa_keys):
    create_route_expecting_user_and_org(app, auth, None, None)
    org_id = str(uuid4())

    response = client.get(route_for(org_id))
    assert response.status_code == 401


def test_require_org_member_with_auth_but_no_org_membership(app, auth, client, rsa_keys):
    create_route_expecting_user_and_org(app, auth, None, None)
    org_id = str(uuid4())

    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)
    response = client.get(route_for(org_id), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 403


def test_require_org_member_with_auth_and_org_member_min_role(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org_min_role(app, auth, user_id, org, "Owner")

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.text == "ok"


def test_require_org_member_with_auth_and_org_member(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org_exact_role(app, auth, user_id, org, "Owner")

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.text == "ok"


def test_require_org_member_with_auth_but_wrong_org_id(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    wrong_org_id = str(uuid4())

    create_route_expecting_user_and_org_exact_role(app, auth, user_id, org, "Owner")

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    # Pass wrong org_id as a path parameter
    response = client.get(route_for(wrong_org_id), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 403


def test_require_org_member_with_auth_but_no_permission(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Member")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org_min_role(app, auth, user_id, org, "Admin")

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 403


def test_require_org_member_with_auth_with_permission(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org_min_role(app, auth, user_id, org, "Admin")

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.text == "ok"


def test_require_org_member_with_auth_by_permission(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin", ["permA"])
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org_by_permission(app, auth, user_id, org, "permA")

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.text == "ok"


def test_require_org_member_with_auth_by_permission_missing(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin", ["permA"])
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org_by_permission(app, auth, user_id, org, "permB")

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 403


def test_require_org_member_with_auth_by_permissions(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin", ["permA", "permB", "permC"])
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org_by_permissions(app, auth, user_id, org, ["permA", "permC"])

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.text == "ok"


def test_require_org_member_with_auth_by_permissions_missing(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin", ["permA"])
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org_by_permissions(app, auth, user_id, org, ["permA", "permB"])

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 403


def test_require_org_member_with_bad_header(app, auth, client, rsa_keys):
    create_route_expecting_user_and_org(app, auth, None, None)

    user_id = random_user_id()
    org = random_org("Admin")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "token " + access_token})
    assert response.status_code == 401


def test_require_org_member_with_wrong_token(app, auth, client, rsa_keys):
    create_route_expecting_user_and_org(app, auth, None, None)
    org_id = str(uuid4())

    response = client.get(route_for(org_id), headers={"Authorization": "Bearer whatisthis"})
    assert response.status_code == 401


def test_require_org_member_with_expired_token(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org_exact_role(app, auth, user_id, org, "Owner")

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem, expires_in=timedelta(minutes=-1))

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 401


def test_require_user_with_bad_issuer(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org_exact_role(app, auth, user_id, org, "Owner")

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem, issuer=HTTP_BASE_AUTH_URL)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 401


def create_route_expecting_user_and_org(app, auth, user_id, org):
    @app.get(ROUTE_NAME)
    async def route(org_id, current_user=Depends(auth.require_user)):
        current_org = auth.require_org_member(current_user, org_id)
        assert current_user.user_id == user_id
        assert current_org.org_id == org["org_id"]
        assert current_org.org_name == org["org_name"]
        return PlainTextResponse("ok")


def create_route_expecting_user_and_org_min_role(app, auth, user_id, org, min_required_role):
    @app.get(ROUTE_NAME)
    async def route(org_id, current_user=Depends(auth.require_user)):
        current_org = auth.require_org_member_with_minimum_role(current_user, org_id, min_required_role)
        assert current_user.user_id == user_id
        assert current_org.org_id == org["org_id"]
        assert current_org.org_name == org["org_name"]
        return PlainTextResponse("ok")


def create_route_expecting_user_and_org_exact_role(app, auth, user_id, org, role):
    @app.get(ROUTE_NAME)
    async def route(org_id, current_user=Depends(auth.require_user)):
        current_org = auth.require_org_member_with_exact_role(current_user, org_id, role)
        assert current_user.user_id == user_id
        assert current_org.org_id == org["org_id"]
        assert current_org.org_name == org["org_name"]
        return PlainTextResponse("ok")


def create_route_expecting_user_and_org_by_permission(app, auth, user_id, org, permission):
    @app.get(ROUTE_NAME)
    async def route(org_id, current_user=Depends(auth.require_user)):
        current_org = auth.require_org_member_with_permission(current_user, org_id, permission)
        assert current_user.user_id == user_id
        assert current_org.org_id == org["org_id"]
        assert current_org.org_name == org["org_name"]
        return PlainTextResponse("ok")


def create_route_expecting_user_and_org_by_permissions(app, auth, user_id, org, permissions):
    @app.get(ROUTE_NAME)
    async def route(org_id, current_user=Depends(auth.require_user)):
        current_org = auth.require_org_member_with_all_permissions(current_user, org_id, permissions)
        assert current_user.user_id == user_id
        assert current_org.org_id == org["org_id"]
        assert current_org.org_name == org["org_name"]
        return PlainTextResponse("ok")


def route_for(org_id):
    return ROUTE_NAME + "?org_id=" + org_id
