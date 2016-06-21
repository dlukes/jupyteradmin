#!/bin/sh

. .venv/bin/activate
gunicorn --reload -b 127.0.0.1:4545 admin:app
