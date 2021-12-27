#!/bin/bash
# build docker image
VERSION=0.1
docker build -t ebiz2go/auth:${VERSION} .
# run docker image using provided environment variable files
# docker run --name backend --link nc-rabbitmq:rabbitmq --link nc-mysql:db --env-file .env -p 8000:8000 bunkdeath/be:${VERSION}
# run bash on backend container
# docker exec -i -t backend /bin/bash