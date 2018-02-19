#!/bin/bash

SECRET_KEY=$(aws ssm get-parameters --names $PS_PATH.django_secret --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

AUTH0_DOMAIN=$(aws ssm get-parameters --names $PS_PATH.auth0_domain --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
AUTH0_CLIENT_ID_VAULT=$(aws ssm get-parameters --names $PS_PATH.auth0_client_id --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
AUTH0_SECRET_VAULT=$(aws ssm get-parameters --names $PS_PATH.auth0_secret --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
AUTH0_SUCCESS_URL_VAULT=$(aws ssm get-parameters --names $PS_PATH.auth0_success_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
AUTHENTICATION_LOGIN_URL_VAULT=$(aws ssm get-parameters --names $PS_PATH.account_server_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
PERMISSION_SERVER_URL_VAULT=$(aws ssm get-parameters --names $PS_PATH.permission_server_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
CONFIRM_EMAIL_URL_VAULT=$(aws ssm get-parameters --names $PS_PATH.confirm_email_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
EMAIL_SALT_VAULT=$(aws ssm get-parameters --names $PS_PATH.email_salt --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
COOKIE_DOMAIN_VAULT=$(aws ssm get-parameters --names $PS_PATH.cookie_domain --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

EMAIL_HOST=$(aws ssm get-parameters --names $PS_PATH.email_host --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
EMAIL_HOST_USER=$(aws ssm get-parameters --names $PS_PATH.email_host_user --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
EMAIL_HOST_PASSWORD=$(aws ssm get-parameters --names $PS_PATH.email_host_password --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
EMAIL_PORT=$(aws ssm get-parameters --names $PS_PATH.email_port --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

MYSQL_USERNAME_VAULT=$(aws ssm get-parameters --names $PS_PATH.mysql_username --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
MYSQL_PASSWORD_VAULT=$(aws ssm get-parameters --names $PS_PATH.mysql_pw --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
MYSQL_HOST_VAULT=$(aws ssm get-parameters --names $PS_PATH.mysql_host --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
MYSQL_PORT_VAULT=$(aws ssm get-parameters --names $PS_PATH.mysql_port --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

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

SSL_KEY=$(aws ssm get-parameters --names $PS_PATH.ssl_key --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
SSL_CERT_CHAIN1=$(aws ssm get-parameters --names $PS_PATH.ssl_cert_chain1 --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
SSL_CERT_CHAIN2=$(aws ssm get-parameters --names $PS_PATH.ssl_cert_chain2 --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
SSL_CERT_CHAIN3=$(aws ssm get-parameters --names $PS_PATH.ssl_cert_chain3 --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

SSL_CERT_CHAIN="$SSL_CERT_CHAIN1$SSL_CERT_CHAIN2$SSL_CERT_CHAIN3"

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

chown -R www-data:www-data /app

gunicorn SciReg.wsgi:application -b 0.0.0.0:8006 --user=www-data --group=www-data

