#!/bin/bash -e

# Perform migrations
python ${DBMI_APP_ROOT}/manage.py migrate

# Check for static files
if [[ -n $DBMI_STATIC_FILES ]]; then

    # Make the directory and collect static files
    mkdir -p "$DBMI_APP_STATIC_ROOT"
    python ${DBMI_APP_ROOT}/manage.py collectstatic --no-input  > /dev/null 2>&1

fi

