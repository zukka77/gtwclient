#!/bin/bash -e

c=$(buildah from gtw-client-base)

buildah copy $c manage.py  /app
buildah copy $c client  /app/client/
buildah copy $c gtwclient  /app/gtwclient/
buildah copy $c env-container  /app/.env
buildah copy --chmod 0755 $c entrypoint.sh /
buildah run $c -- /bin/sh -c 'cd /app;/venv/bin/python manage.py collectstatic'
buildah run $c -- adduser -D app
buildah run $c -- chown -R app: /venv
buildah run $c -- chown -R app: /app
buildah config --cmd "" $c
buildah config --entrypoint '["/entrypoint.sh"]' $c
buildah config --port 4000 $c
buildah commit --rm $c gtwclient
