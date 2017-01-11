# SciReg

This service keeps track of user information. Like the other Sci projects this service uses the DBMI_JWT to maintain an identity session.

## Required Configurations

In order to verify the signature on the JWT we need the same secret as it was signed with in Auth0. You'll see the below setting which utilizes this secret. This service has both form based and REST call based authentication.

### Auth0

~~~
JWT_AUTH = {
    'JWT_SECRET_KEY': base64.b64decode(os.environ.get("AUTH0_SECRET", ""), '-_'),
    'JWT_AUDIENCE': os.environ.get("AUTH0_CLIENT_ID"),
    'JWT_PAYLOAD_GET_USERNAME_HANDLER': 'registration.permissions.jwt_get_username_from_payload'
}

AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
AUTH0_SECRET = os.environ.get("AUTH0_SECRET")
AUTH0_SUCCESS_URL = os.environ.get("AUTH0_SUCCESS_URL")
AUTH0_LOGOUT_URL = os.environ.get("AUTH0_LOGOUT_URL")
~~~

### Other configs
~~~python
# Django config, move this to an ENV in the future
ALLOWED_HOSTS = ['authentication.aws.dbmi.hms.harvard.edu']
~~~