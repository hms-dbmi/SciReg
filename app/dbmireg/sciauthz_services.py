import requests
import logging
from furl import furl

from json import JSONDecodeError

from dbmireg import settings

logger = logging.getLogger(__name__)

VERIFY_SSL = True

def get_sciauthz_project(project):
    logger.debug("Request project info for: " + project)

    f = furl(settings.DBMI_AUTHZ_URL)
    f.path.add('project')

    data = {'project': project}

    try:
        # Make the request.
        response = requests.post(f.url, data=data)
        logger.debug("Project response: {}".format(response))
    except Exception as e:
        logger.exception(e)
        raise

    return response


def user_has_manage_permission(jwt_headers, project):
    logger.debug("Checking user permission for project: {}".format(project))

    f = furl(settings.DBMI_AUTHZ_URL)
    f.path.add('user_permission/')

    f.args["item"] = project

    is_manager = False
    try:
        user_permissions = requests.get(f.url, headers=jwt_headers, verify=VERIFY_SSL).json()
        logger.debug("Permission returned: {}".format(user_permissions))

        if user_permissions is not None and 'results' in user_permissions:
            for perm in user_permissions['results']:
                if perm['permission'] == "MANAGE":
                    is_manager = True

    except JSONDecodeError as e:
        logger.exception(e)
    except Exception as e:
        logger.exception(e)

    logger.debug("Is manager: {}".format(is_manager))
    return is_manager


def user_has_single_profile_view_permission(jwt_headers, project, email):
    logger.debug("Checking user single profile view permission for project: {}".format(project))

    f = furl(settings.DBMI_AUTHZ_URL)
    f.path.add('user_permission/')

    f.args["item"] = "dbmireg.%s.profile.%s" % (project, email)

    try:
        user_permissions = requests.get(f.url, headers=jwt_headers, verify=VERIFY_SSL).json()
        logger.debug("Permission returned: {}".format(user_permissions))

        if user_permissions["count"] > 0:
            return user_permissions["results"][0]["permission"] == "VIEW"

    except JSONDecodeError as e:
        logger.exception(e)

    return False


def check_view_profile_permission(jwt, project, email):
    logger.debug("Checking view profile permission for project: {}".format(project))

    jwt_headers = {"Authorization": "JWT " + jwt, 'Content-Type': 'application/json'}

    logger.debug("Checking manager status")

    manager = user_has_manage_permission(jwt_headers, project)

    logger.debug("Checking single permission status")

    single_perm = user_has_single_profile_view_permission(jwt_headers, project, email)

    logger.debug("(manager, single_perm) (%s, %s)" % (manager, single_perm))

    return manager or single_perm

