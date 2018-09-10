FROM python:3.6-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nginx \
        jq \
        curl \
        openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install some pip packages
RUN pip install awscli boto3 gunicorn shinto-cli dumb-init

# Add requirements
ADD requirements.txt /requirements.txt

# Build and install python requirements
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    default-libmysqlclient-dev g++ \
    && pip install -r /requirements.txt && \
    apt-get remove --purge -y g++ \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/* \
    && apt-get autoremove -y

# Copy templates
ADD docker-entrypoint-templates.d/ /docker-entrypoint-templates.d/

# Setup entry scripts
ADD docker-entrypoint-init.d/ /docker-entrypoint-init.d/
ADD docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod a+x docker-entrypoint.sh

# Copy app source
COPY ./app /app

# Set the build env
ENV DBMI_ENV=prod

# Set app parameters
ENV DBMI_PARAMETER_STORE_PREFIX=dbmi.reg.${DBMI_ENV}
ENV DBMI_PARAMETER_STORE_PRIORITY=true
ENV DBMI_AWS_REGION=us-east-1

# App config
ENV DBMI_APP_ROOT=/app
ENV DBMI_APP_DOMAIN=registration.dbmi.hms.harvard.edu

# Load balancing
ENV DBMI_LB=true
ENV DBMI_APP_HEALTHCHECK_PATH=/healthcheck

# Set nginx and network parameters
ENV DBMI_GUNICORN_PORT=8000
ENV DBMI_PORT=443
ENV DBMI_NGINX_USER=www-data
ENV DBMI_NGINX_PID_PATH=/var/run/nginx.pid

# SSL and load balancing
ENV DBMI_SSL=true
ENV DBMI_CREATE_SSL=true
ENV DBMI_SSL_PATH=/etc/nginx/ssl

# Static files
ENV DBMI_STATIC_FILES=true
ENV DBMI_APP_STATIC_URL_PATH=/static
ENV DBMI_APP_STATIC_ROOT=/app/assets

# Healthchecks
ENV DBMI_HEALTHCHECK=true
ENV DBMI_HEALTHCHECK_PATH=/healthcheck

ENTRYPOINT ["dumb-init", "/docker-entrypoint.sh"]

CMD gunicorn dbmireg.wsgi:application -b 0.0.0.0:${DBMI_GUNICORN_PORT} \
    --user ${DBMI_NGINX_USER} --group ${DBMI_NGINX_USER} --chdir=${DBMI_APP_ROOT}