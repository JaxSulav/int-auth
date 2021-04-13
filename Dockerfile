# set the base image 
FROM python:3.6-slim


RUN apt-get update
# RUN apt-get install -y mysql-client
RUN pip install --upgrade pip

#add project files to the usr/src/app folder
ADD . /usr/src/app

#set directoty where CMD will execute 
WORKDIR /usr/src/app

COPY requirements.txt ./
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

# Expose ports
EXPOSE 8000

# ENV DEBUG=False
# ENV DB_HOST=db
# ENV DB_PORT=3306
# ENV DB_NAME=auth
# ENV DB_USER=auth_user
# ENV DB_PASS=changeme

# Get pip to download and install requirements:
RUN pip install --no-cache-dir -r requirements.txt
# RUN python manage.py collectstatic --noinput

ENTRYPOINT [ "/entrypoint.sh" ]
