<p align="center">
  <a href="https://www.propelauth.com?ref=github" target="_blank" align="center">
    <img src="https://www.propelauth.com/imgs/lockup.svg" width="200">
  </a>
</p>

# PropelAuth FastAPI SDK

A FastAPI library for managing authentication, backed by [PropelAuth](https://www.propelauth.com/?utm_campaign=github-fastapi).

[PropelAuth](https://www.propelauth.com?ref=github) makes it easy to add authentication and authorization to your B2B/multi-tenant application.

Your frontend gets a beautiful, safe, and customizable login screen. Your backend gets easy authorization with just a few lines of code. You get an easy-to-use dashboard to config and manage everything.

## Documentation

- Full reference this library is [here](https://docs.propelauth.com/reference/backend-apis/fastapi)
- Getting started guides for PropelAuth are [here](https://docs.propelauth.com/)

## Installation

```bash
pip install propelauth_fastapi
```

## Initialize

`init_auth` performs a one-time initialization of the library. 
It will verify your `api_key` is correct and fetch the metadata needed to verify access tokens in [require_user](#require-user) or [optional_user](#optional-user).

```py 
from propelauth_fastapi import init_auth

auth = init_auth("YOUR_AUTH_URL", "YOUR_API_KEY")
```

# Protect API Routes

Protecting an API route is as simple as adding a [dependency](https://fastapi.tiangolo.com/tutorial/dependencies/) to your route. 

None of the dependencies make a external request to PropelAuth. 
    They all are verified locally using the [access token](https://docs.propelauth.com/guides-and-examples/guides/access-tokens) provided in the request, making it very fast.

## require_user

A dependency that will verify the request was made by a valid user. 
If a valid [access token](https://docs.propelauth.com/guides-and-examples/guides/access-tokens) is provided, it will return a [User](https://docs.propelauth.com/reference/backend-apis/fastapi#user) object. 
If not, the request is rejected with a 401 status code.

```py
from fastapi import FastAPI, Depends
from propelauth_fastapi import init_auth, User

app = FastAPI()
auth = init_auth("AUTH_URL", "API_KEY")

@app.get("/")
async def root(current_user: User = Depends(auth.require_user)):
    return {"message": f"Hello {current_user.user_id}"}
```

## optional_user

Similar to [require_user](#require-user), but will return `None` if no valid access token is provided.

```py
from typing import Optional

from fastapi import FastAPI, Depends
from propelauth_fastapi import init_auth, User

app = FastAPI()
auth = init_auth("AUTH_URL", "API_KEY")

@app.get("/api/whoami_optional")
async def whoami_optional(current_user: Optional[User] = Depends(auth.optional_user)):
    if current_user:
        return {"user_id": current_user.user_id}
    return {}
```

# Authorization / Organizations

You can also verify which organizations the user is in, and which roles and permissions they have in each organization all through the [User](https://docs.propelauth.com/reference/backend-apis/fastapi#user) or [OrgMemberInfo](https://docs.propelauth.com/reference/backend-apis/fastapi#org-member-info) objects.

## Check Org Membership

Verify that the request was made by a valid user **and** that the user is a member of the specified organization. This can be done using the [User](https://docs.propelauth.com/reference/backend-apis/fastapi#user) object.

```py
@app.get("/api/org/{org_id}")
async def org_membership(org_id: str, current_user: User = Depends(auth.require_user)):
    org = current_user.get_org(org_id)
    if org == None:
        raise HTTPException(status_code=403, detail="Forbidden")
    return f"You are in org {org.org_name}"
```

## Check Org Membership and Role

Similar to checking org membership, but will also verify that the user has a specific Role in the organization. This can be done using either the [User](https://docs.propelauth.com/reference/backend-apis/fastapi#user) or [OrgMemberInfo](https://docs.propelauth.com/reference/backend-apis/fastapi#org-member-info) objects.

A user has a Role within an organization. By default, the available roles are Owner, Admin, or Member, but these can be configured. These roles are also hierarchical, so Owner > Admin > Member.

```py
## Assuming a Role structure of Owner => Admin => Member

@app.get("/api/org/{org_id}")
def org_owner(org_id: str, current_user: User = Depends(auth.require_user)):
    org = current_user.get_org(org_id)
    if (org == None) or (org.user_is_role("Owner") == False):
        raise HTTPException(status_code=403, detail="Forbidden")
    return f"You are an Owner in org {org.org_name}"
```

## Check Org Membership and Permission

Similar to checking org membership, but will also verify that the user has the specified permission in the organization. This can be done using either the [User](https://docs.propelauth.com/reference/backend-apis/fastapi#user) or [OrgMemberInfo](https://docs.propelauth.com/reference/backend-apis/fastapi#org-member-info) objects.

Permissions are arbitrary strings associated with a role. For example, `can_view_billing`, `ProductA::CanCreate`, and `ReadOnly` are all valid permissions. 
You can create these permissions in the PropelAuth dashboard.

```py
@app.get("/api/org/{org_id}")
def org_billing(org_id: str, current_user: User = Depends(auth.require_user)):
    org = current_user.get_org(org_id)
    if (org == None) or (org.user_has_permission("can_view_billing") == False):
        raise HTTPException(status_code=403, detail="Forbidden")
    return Response(f"You can view billing information for org {org.org_name}")
```

## Calling Backend APIs

You can also use the library to call the PropelAuth APIs directly, allowing you to fetch users, create orgs, and a lot more. 
See the [API Reference](https://docs.propelauth.com/reference) for more information.

```py
from propelauth_fastapi import init_auth

auth = init_auth("YOUR_AUTH_URL", "YOUR_API_KEY")

magic_link = auth.create_magic_link(email="test@example.com")
```

## Questions?

Feel free to reach out at support@propelauth.com
