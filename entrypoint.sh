#!/bin/bash
set -e

if [ $# -gt 0 ];then
    exec "$@"
fi


cd /app
touch client_auth
chmod 400 client_auth
touch client_sign
chmod 400 client_sign
if [ -z "$NO_CLIENT_AUTH"];then
    if [ -n "$CLIENT_AUTH" ];then
       echo "$CLIENT_AUTH">client_auth
    else
        openssl req -newkey rsa:2048 -keyout client.key -x509 -days 365 -nodes -out client.crt -subj "/CN=DEMO" -days 365
        cat client.key client.crt > client_auth
    fi
    
    if [ -n "$CLIENT_SIGN" ];then
        echo "$CLIENT_SIGN  ">client_sign
    else
        openssl req -newkey rsa:2048 -keyout client.key -x509 -days 365 -nodes -out client.crt -subj "/CN=DEMO" -days 365
        cat client.key client.crt > client_sign
    fi
else
    #GENERATE FAKE CERT
    openssl req -newkey rsa:2048 -keyout client.key -x509 -days 365 -nodes -out client.crt -subj "/CN=DEMO" -days 365
    cat client.key client.crt > client_auth
    cat client_auth > client_sign
fi
chown app: client_auth
chown app: client_sign


su  app -c '/venv/bin/python ./manage.py makemigrations'
su  app -c '/venv/bin/python ./manage.py migrate'



grep SECRET_KEY .env || RES=$?
if [ $RES -ne 0 ];then
    SECRET=$(python -c "import secrets;print(secrets.token_hex())")
    echo -e "\nSECRET_KEY=${SECRET}\n" >> .env
fi


su  app -c '/venv/bin/python ./manage.py have_superuser --silent ' || RES=$?

if [  $RES -ne 0 ];then
    echo "no superuser detected creating one"
    PASSWORD=${ADMIN_PASSWORD:-password}
    USER=${ADMIN_USER:-root}
    su  app -c "/venv/bin/python ./manage.py ensure_superuser --username $USER --password $PASSWORD"
fi

exec su  app -c '/venv/bin/gunicorn -b 0.0.0.0:4000 -w4 --threads 16 --access-logfile - --error-logfile - -t300 gtwclient.wsgi'

