# SciReg

This service keeps track of user information. Like the other Sci projects this service uses the DBMI_JWT to maintain an identity session.

## Required Configurations

In order to verify the signature on the JWT we need the same secret as it was signed with in Auth0. You'll see the below setting which utilizes this secret. This service has both form based and REST call based authentication.

### Auth0

~~~
AUTH0_CLIENT_ID_LIST = os.environ.get("AUTH0_CLIENT_ID_LIST")
AUTH0_SECRET = os.environ.get("AUTH0_SECRET")
AUTH0_SUCCESS_URL = os.environ.get("AUTH0_SUCCESS_URL")
AUTH0_LOGOUT_URL = os.environ.get("AUTH0_LOGOUT_URL")
~~~

### Other configs
~~~python
# Django config, move this to an ENV in the future
ALLOWED_HOSTS = ['registration.aws.dbmi.hms.harvard.edu']
~~~

