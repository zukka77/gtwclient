#!/bin/sh
set -e

if [ $# -gt 0 ];then
    exec "$@"
fi


cd /app
if [ -z "$CLIENT_AUTH" ];then
    echo "must supply CLIENT_AUTH environment variable as concatenated TLS key and certificate"
    exit 1
fi
if [ -z "$CLIENT_SIGN" ];then
    echo "must supply CLIENT_SIGN environment variable as concatenated TLS key and certificate"
    exit 1
fi

touch client_auth
chmod 400 client_auth
echo "$CLIENT_AUTH">client_auth
chown app: client_auth
touch client_sign
chmod 400 client_sign
echo "$CLIENT_SIGN  ">client_sign
chown app: client_sign

su  app -c '/venv/bin/python ./manage.py makemigrations'
su  app -c '/venv/bin/python ./manage.py migrate'

su  app -c '/venv/bin/python ./manage.py have_superuser --silent ' || RES=$?

grep SECRET_KEY .env || RES=$?
if [ $RES -ne 0 ];then
    SECRET=$(python -c "import secrets;print(secrets.token_hex())")
    echo -e "\nSECRET_KEY=${SECRET}\n" >> .env
fi

if [  $RES -ne 0 ];then
    echo "no superuser detected creating one"
    PASSWORD=${ADMIN_PASSWORD:-password}
    USER=${ADMIN_USER:-root}
    su  app -c "/venv/bin/python ./manage.py ensure_superuser --username $USER --password $PASSWORD"
fi

exec su  app -c '/venv/bin/gunicorn -b 0.0.0.0:4000 -w4  --access-logfile - --error-logfile - -t16 gtwclient.wsgi'

