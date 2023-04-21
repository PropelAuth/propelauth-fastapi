from collections import namedtuple
from typing import List

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from propelauth_py import TokenVerificationMetadata, init_base_auth, Auth
from propelauth_py.errors import ForbiddenException, UnauthorizedException
from propelauth_py.user import User

_security = HTTPBearer(auto_error=False)


class RequiredUserDependency:
    def __init__(self, auth: Auth, debug_mode: bool):
        self.auth = auth
        self.debug_mode = debug_mode

    def __call__(self, credentials: HTTPAuthorizationCredentials = Depends(_security)):
        try:
            # Pass it in to the underlying function to get consistent error messages
            if credentials is None:
                authorization_header = ""
            else:
                authorization_header = credentials.scheme + " " + credentials.credentials

            user = self.auth.validate_access_token_and_get_user(authorization_header)
            return user
        except UnauthorizedException as e:
            if self.debug_mode:
                raise HTTPException(status_code=401, detail=e.message)
            else:
                raise HTTPException(status_code=401)


class OptionalUserDependency:
    def __init__(self, auth: Auth):
        self.auth = auth

    def __call__(self, credentials: HTTPAuthorizationCredentials = Depends(_security)):
        if credentials is None:
            return None

        try:
            authorization_header = credentials.scheme + " " + credentials.credentials
            user = self.auth.validate_access_token_and_get_user(authorization_header)
            return user
        except UnauthorizedException:
            return None


def _require_org_member_wrapper(auth: Auth, debug_mode: bool):
    def require_org_member(user: User, required_org_id: str):
        try:
            return auth.validate_org_access_and_get_org(user, required_org_id)
        except ForbiddenException as e:
            _handle_forbidden_exception(e, debug_mode)

    return require_org_member


def _require_org_member_with_minimum_role_wrapper(auth: Auth, debug_mode: bool):
    def require_org_member_with_minimum_role(user: User, required_org_id: str, minimum_required_role: str):
        try:
            return auth.validate_minimum_org_role_and_get_org(user, required_org_id, minimum_required_role)
        except ForbiddenException as e:
            _handle_forbidden_exception(e, debug_mode)

    return require_org_member_with_minimum_role


def _require_org_member_with_exact_role_wrapper(auth: Auth, debug_mode: bool):
    def require_org_member_with_exact_role(user: User, required_org_id: str, role: str):
        try:
            return auth.validate_exact_org_role_and_get_org(user, required_org_id, role)
        except ForbiddenException as e:
            _handle_forbidden_exception(e, debug_mode)

    return require_org_member_with_exact_role


def _require_org_member_with_permission_wrapper(auth: Auth, debug_mode: bool):
    def require_org_member_with_permission(user: User, required_org_id: str, permission: str):
        try:
            return auth.validate_permission_and_get_org(user, required_org_id, permission)
        except ForbiddenException as e:
            _handle_forbidden_exception(e, debug_mode)

    return require_org_member_with_permission


def _require_org_member_with_all_permissions_wrapper(auth: Auth, debug_mode: bool):
    def require_org_member_with_all_permissions(user: User, required_org_id: str, permissions: List[str]):
        try:
            return auth.validate_all_permissions_and_get_org(user, required_org_id, permissions)
        except ForbiddenException as e:
            _handle_forbidden_exception(e, debug_mode)

    return require_org_member_with_all_permissions


def _handle_forbidden_exception(e: ForbiddenException, debug_mode: bool):
    if debug_mode:
        raise HTTPException(status_code=403, detail=e.message)
    else:
        raise HTTPException(status_code=403)



Auth = namedtuple("Auth", [
    "require_user", "optional_user",
    "require_org_member",
    "require_org_member_with_minimum_role",
    "require_org_member_with_exact_role",
    "require_org_member_with_permission",
    "require_org_member_with_all_permissions",
    "fetch_user_metadata_by_user_id", "fetch_user_metadata_by_email", "fetch_user_metadata_by_username",
    "fetch_batch_user_metadata_by_user_ids",
    "fetch_batch_user_metadata_by_emails",
    "fetch_batch_user_metadata_by_usernames",
    "fetch_org", "fetch_org_by_query", "fetch_users_by_query", "fetch_users_in_org",
    "create_user",
    "update_user_email",
    "update_user_metadata",
    "update_user_password",
    "create_magic_link", "create_access_token",
    "migrate_user_from_external_source", "create_org", "add_user_to_org",
    "update_org_metadata",
    "delete_user", "disable_user", "enable_user",
    "allow_org_to_setup_saml_connection", "disallow_org_to_setup_saml_connection"
])


def init_auth(auth_url: str, api_key: str, token_verification_metadata: TokenVerificationMetadata = None,
              debug_mode=False):
    """Fetches metadata required to validate access tokens and returns auth decorators and utilities"""

    auth = init_base_auth(auth_url, api_key, token_verification_metadata)
    return Auth(
        require_user=RequiredUserDependency(auth, debug_mode),
        optional_user=OptionalUserDependency(auth),
        require_org_member=_require_org_member_wrapper(auth, debug_mode),
        require_org_member_with_minimum_role=_require_org_member_with_minimum_role_wrapper(auth, debug_mode),
        require_org_member_with_exact_role=_require_org_member_with_exact_role_wrapper(auth, debug_mode),
        require_org_member_with_permission=_require_org_member_with_permission_wrapper(auth, debug_mode),
        require_org_member_with_all_permissions=_require_org_member_with_all_permissions_wrapper(auth, debug_mode),
        fetch_user_metadata_by_user_id=auth.fetch_user_metadata_by_user_id,
        fetch_user_metadata_by_email=auth.fetch_user_metadata_by_email,
        fetch_user_metadata_by_username=auth.fetch_user_metadata_by_username,
        fetch_batch_user_metadata_by_user_ids=auth.fetch_batch_user_metadata_by_user_ids,
        fetch_batch_user_metadata_by_emails=auth.fetch_batch_user_metadata_by_emails,
        fetch_batch_user_metadata_by_usernames=auth.fetch_batch_user_metadata_by_usernames,
        fetch_org=auth.fetch_org,
        fetch_org_by_query=auth.fetch_org_by_query,
        fetch_users_by_query=auth.fetch_users_by_query,
        fetch_users_in_org=auth.fetch_users_in_org,
        create_user=auth.create_user,
        update_user_email=auth.update_user_email,
        update_user_metadata=auth.update_user_metadata,
        update_user_password=auth.update_user_password,
        create_magic_link=auth.create_magic_link,
        create_access_token=auth.create_access_token,
        migrate_user_from_external_source=auth.migrate_user_from_external_source,
        create_org=auth.create_org,
        add_user_to_org=auth.add_user_to_org,
        update_org_metadata=auth.update_org_metadata,
        enable_user=auth.enable_user,
        disable_user=auth.disable_user,
        delete_user=auth.delete_user,
        allow_org_to_setup_saml_connection=auth.allow_org_to_setup_saml_connection,
        disallow_org_to_setup_saml_connection=auth.disallow_org_to_setup_saml_connection,
    )
