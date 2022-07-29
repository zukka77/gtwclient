FROM docker.io/python:alpine as base
RUN python -m venv /venv
RUN apk add gcc g++ qpdf-dev
RUN /venv/bin/pip install -U pip --no-cache-dir
RUN /venv/bin/pip install wheel --no-cache-dir
RUN mkdir /app
COPY requirements.txt /app
RUN /venv/bin/pip install -r /app/requirements.txt --no-cache-dir

FROM docker.io/python:alpine as intermediate
RUN apk add qpdf
RUN rm -rf /var/cache/apk/*
COPY --from=base /venv /venv
COPY --from=base /app /app
COPY manage.py  /app
COPY client  /app/client/
COPY gtwclient  /app/gtwclient/
COPY env-container  /app/.env
COPY entrypoint.sh /
RUN chmod 0755 /entrypoint.sh
RUN cd /app;/venv/bin/python manage.py collectstatic -c
RUN adduser -D app
RUN chown -R app: /venv
RUN chown -R app: /app
ENTRYPOINT ["/entrypoint.sh"]
WORKDIR /app
EXPOSE 4000/tcp

