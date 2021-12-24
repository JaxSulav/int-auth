#!/bin/bash

>&2 echo "Waiting for database to start"

# wait for the postgres docker to be running
while ! nc db 5432; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 0.1
done

>&2 echo "Postgres is up - executing command"

# Apply database migrations
echo "Apply database migrations"
python manage.py migrate

# # Start server
echo "Starting server"
gunicorn main.wsgi:application --bind 0.0.0.0:8000 --reload
