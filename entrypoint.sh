#!/bin/bash

#>&2 echo "Waiting for database to start"

# wait for the postgres docker to be running
#until psql -h db -U "postgres" -c '\l'; do
#  >&2 echo "Postgresql is unavailable - sleeping"
#  sleep 1
#done
#
#>&2 echo "Postgres is up - executing command"

# Apply database migrations
echo "Apply database migrations"
python manage.py migrate

echo "Starting application"
gunicorn main.wsgi:application --bind 0.0.0.0:8000 --reload --log-level debug
