FROM docker.io/python:3 as base
RUN python -m venv /venv
RUN /venv/bin/pip install -U pip --no-cache-dir
RUN /venv/bin/pip install wheel --no-cache-dir
RUN mkdir -p /app/client
RUN mkdir -p /app/gtwclient
COPY requirements.txt /app
RUN /venv/bin/pip install -r /app/requirements.txt --no-cache-dir
RUN useradd app
RUN chown -R app: /venv
COPY env-container  /app/.env
COPY entrypoint.sh /
RUN chmod 0755 /entrypoint.sh
COPY manage.py  /app
COPY ./gtwclient  /app/gtwclient/
COPY ./client  /app/client/
RUN cd /app;/venv/bin/python manage.py collectstatic -c
RUN chown -R app: /app
ENTRYPOINT ["/entrypoint.sh"]
WORKDIR /app
EXPOSE 4000/tcp

