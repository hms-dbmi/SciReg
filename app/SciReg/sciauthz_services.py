import requests
import logging
from furl import furl

from json import JSONDecodeError

from SciReg import settings

logger = logging.getLogger(__name__)

VERIFY_SSL = True

def get_sciauthz_project(project):

    logger.debug("[SCIREG][DEBUG][sciauthz_services] - Request project info for: " + project)

    f = furl(settings.PERMISSION_SERVER_URL)
    f.path.add('project')

    data = {'project': project}

    try:
        # Make the request.
        response = requests.post(f.url, data=data)
    except Exception as e:
        logger.error("[SCIAUTH][ERROR][sciauthz_services] - Exception: " + str(e))
        raise

    return response


def user_has_manage_permission(jwt_headers, project):
    is_manager = False

    f = furl(settings.PERMISSION_SERVER_URL)
    f.path.add('user_permission/')

    f.args["item"] = project

    try:
        user_permissions = requests.get(f.url, headers=jwt_headers, verify=VERIFY_SSL).json()
    except JSONDecodeError:
        user_permissions = None
        logger.debug("[SCIREG][DEBUG][user_has_manage_permission] - No Valid permissions returned.")
    except Exception as e:
        logger.debug("SCIREG][DEBUG][user_has_manage_permission] - " + e)

    if user_permissions is not None and 'results' in user_permissions:
        for perm in user_permissions['results']:
            if perm['permission'] == "MANAGE":
                is_manager = True

    return is_manager


def user_has_single_profile_view_permission(jwt_headers, project, email):

    f = furl(settings.PERMISSION_SERVER_URL)
    f.path.add('user_permission/')

    f.args["item"] = "SciReg.%s.profile.%s" % (project, email)

    try:
        user_permissions = requests.get(f.url, headers=jwt_headers, verify=VERIFY_SSL).json()
    except JSONDecodeError:
        logger.debug("[SCIREG][DEBUG][user_has_single_profile_view_permission] - No Valid permissions returned.")
        user_permissions = {"count":0}

    if user_permissions["count"] > 0:
        return user_permissions["results"][0]["permission"] == "VIEW"
    else:
        return False


def check_view_profile_permission(jwt, project, email):

    jwt_headers = {"Authorization": "JWT " + jwt.decode('utf-8'), 'Content-Type': 'application/json'}

    logger.debug("[SCIREG][DEBUG][check_view_profile_permission] - Checking manager status.")

    manager = user_has_manage_permission(jwt_headers, project)

    logger.debug("[SCIREG][DEBUG][check_view_profile_permission] - Checking single permission status.")

    single_perm = user_has_single_profile_view_permission(jwt_headers, project, email)

    logger.debug("[SCIREG][DEBUG][check_view_profile_permission] - (manager, single_perm) (%s, %s)" % (manager, single_perm))

    return manager or single_perm

