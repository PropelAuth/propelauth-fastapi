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
    "fetch_batch_user_metadata_by_usernames"
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
    )
