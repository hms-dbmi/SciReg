import requests
import logging
from furl import furl

from SciReg import settings

logger = logging.getLogger(__name__)


def get_sciauthz_project(project):

    logger.debug("[SCIREG][DEBUG][sciauthz_services] - Request project info for: " + project)

    # Build the url.
    f = furl(settings.SCIAUTHZ_URL)
    f.path.add('project')

    # Set the data for the request.
    data = {'project': project}

    try:
        # Make the request.
        response = requests.post(f.url, data=data)
    except Exception as e:
        logger.error("[SCIAUTH][ERROR][sciauthz_services] - Exception: " + str(e))
        raise

    return response
