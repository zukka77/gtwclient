#!/bin/bash -e

c=$(buildah from docker.io/python:alpine)

buildah run $c -- python -m venv /venv
buildah run $c -- apk add gcc g++ qpdf-dev
buildah run $c -- /venv/bin/pip install -U pip --no-cache-dir
buildah run $c mkdir /app
buildah copy $c requirements.txt /app
buildah run $c  -- /venv/bin/pip install -r /app/requirements.txt


c2=$(buildah from docker.io/python:alpine)
buildah run $c2 -- apk add qpdf
buildah run $c2 -- rm -rf /var/cache/apk/*
buildah copy --from $c $c2 /venv /venv
buildah copy --from $c $c2 /app /app