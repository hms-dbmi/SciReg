#!/bin/bash

echo $ONETIME_TOKEN

/vault/vault auth $ONETIME_TOKEN

SECRET_KEY=$(/vault/vault read -field=value $VAULT_PATH/django_secret)

AUTH0_DOMAIN=$(/vault/vault read -field=value $VAULT_PATH/auth0_domain)
AUTH0_CLIENT_ID_VAULT=$(/vault/vault read -field=value $VAULT_PATH/auth0_client_id)
AUTH0_SECRET_VAULT=$(/vault/vault read -field=value $VAULT_PATH/auth0_secret)
AUTH0_SUCCESS_URL_VAULT=$(/vault/vault read -field=value $VAULT_PATH/auth0_success_url)
AUTHENTICATION_LOGIN_URL_VAULT=$(/vault/vault read -field=value $VAULT_PATH/account_server_url)
PERMISSION_SERVER_URL_VAULT=$(/vault/vault read -field=value $VAULT_PATH/permission_server_url)
CONFIRM_EMAIL_URL_VAULT=$(/vault/vault read -field=value $VAULT_PATH/confirm_email_url)
EMAIL_SALT_VAULT=$(/vault/vault read -field=value $VAULT_PATH/email_salt)
COOKIE_DOMAIN_VAULT=$(/vault/vault read -field=value $VAULT_PATH/cookie_domain)

EMAIL_HOST=$(/vault/vault read -field=value $VAULT_PATH/email_host)
EMAIL_HOST_USER=$(/vault/vault read -field=value $VAULT_PATH/email_host_user)
EMAIL_HOST_PASSWORD=$(/vault/vault read -field=value $VAULT_PATH/email_host_password)
EMAIL_PORT=$(/vault/vault read -field=value $VAULT_PATH/email_port)

MYSQL_USERNAME_VAULT=$(/vault/vault read -field=value $VAULT_PATH/mysql_username)
MYSQL_PASSWORD_VAULT=$(/vault/vault read -field=value $VAULT_PATH/mysql_pw)
MYSQL_HOST_VAULT=$(/vault/vault read -field=value $DB_VAULT_PATH/mysql_host)
MYSQL_PORT_VAULT=$(/vault/vault read -field=value $VAULT_PATH/mysql_port)

export SECRET_KEY
export AUTH0_DOMAIN
export AUTH0_CLIENT_ID=$AUTH0_CLIENT_ID_VAULT
export AUTH0_SECRET=$AUTH0_SECRET_VAULT
export AUTH0_SUCCESS_URL=$AUTH0_SUCCESS_URL_VAULT
export AUTHENTICATION_LOGIN_URL=$AUTHENTICATION_LOGIN_URL_VAULT
export PERMISSION_SERVER_URL=$PERMISSION_SERVER_URL_VAULT
export CONFIRM_EMAIL_URL=$CONFIRM_EMAIL_URL_VAULT
export EMAIL_SALT=$EMAIL_SALT_VAULT
export COOKIE_DOMAIN=$COOKIE_DOMAIN_VAULT

export MYSQL_USERNAME=$MYSQL_USERNAME_VAULT
export MYSQL_PASSWORD=$MYSQL_PASSWORD_VAULT
export MYSQL_HOST=$MYSQL_HOST_VAULT
export MYSQL_PORT=$MYSQL_PORT_VAULT

export EMAIL_HOST
export EMAIL_HOST_USER
export EMAIL_HOST_PASSWORD
export EMAIL_PORT

SSL_KEY=$(/vault/vault read -field=value $VAULT_PATH/ssl_key)
SSL_CERT_CHAIN=$(/vault/vault read -field=value $VAULT_PATH/ssl_cert_chain)

echo $SSL_KEY | base64 -d >> /etc/nginx/ssl/server.key
echo $SSL_CERT_CHAIN | base64 -d >> /etc/nginx/ssl/server.crt

cd /app/

python manage.py migrate

if [ ! -d static ]; then
  mkdir static
fi
python manage.py collectstatic --no-input

python manage.py shell -c "from django.contrib.auth.models import User; User.objects.create_superuser('$ADMIN_EMAIL', '$ADMIN_EMAIL', '')" || echo "Super User already exists."

/etc/init.d/nginx restart

gunicorn SciReg.wsgi:application -b 0.0.0.0:8006

