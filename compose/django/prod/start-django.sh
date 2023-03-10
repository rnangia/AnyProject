#!/bin/sh

python3 manage.py collectstatic --noinput
uwsgi --socket 0.0.0.0:8000 --module config.wsgi
