from collections import namedtuple

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from propelauth_py import TokenVerificationMetadata, init_base_auth, Auth
from propelauth_py.errors import ForbiddenException, UnauthorizedException, UnexpectedException
from propelauth_py.user import User, UserRole

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
    def require_org_member(user: User, required_org_id: str, minimum_required_role: UserRole = None):
        try:
            return auth.validate_org_access_and_get_org(user, required_org_id, minimum_required_role)
        except ForbiddenException as e:
            if debug_mode:
                raise HTTPException(status_code=403, detail=e.message)
            else:
                raise HTTPException(status_code=403)
        except UnexpectedException as e:
            if debug_mode:
                raise HTTPException(status_code=500, detail=e.message)
            else:
                raise HTTPException(status_code=500)

    return require_org_member


Auth = namedtuple("Auth", [
    "require_user", "optional_user", "require_org_member",
    "fetch_user_metadata_by_user_id", "fetch_user_metadata_by_email", "fetch_user_metadata_by_username",
    "fetch_batch_user_metadata_by_user_ids",
    "fetch_batch_user_metadata_by_emails",
    "fetch_batch_user_metadata_by_usernames",
    "fetch_org", "fetch_org_by_query", "fetch_users_by_query", "fetch_users_in_org",
    "create_user",
    "update_user_email",
    "update_user_metadata",
    "create_magic_link", "migrate_user_from_external_source", "create_org", "add_user_to_org"
])


def init_auth(auth_url: str, api_key: str, token_verification_metadata: TokenVerificationMetadata = None,
              debug_mode=False):
    """Fetches metadata required to validate access tokens and returns auth decorators and utilities"""

    auth = init_base_auth(auth_url, api_key, token_verification_metadata)
    return Auth(
        require_user=RequiredUserDependency(auth, debug_mode),
        optional_user=OptionalUserDependency(auth),
        require_org_member=_require_org_member_wrapper(auth, debug_mode),
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
        create_magic_link=auth.create_magic_link,
        migrate_user_from_external_source=auth.migrate_user_from_external_source,
        create_org=auth.create_org,
        add_user_to_org=auth.add_user_to_org,
    )
