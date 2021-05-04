# History Service

This service deals with the authentication and authorization of the user.


# Prerequisite

Python 3.6.8


# Installation

## **Host Machine**
Inorder to run on the host machine, create a python virtual environment and run the application.

### **Create Virtual Environment**

To create the virtual environment, use the following command line. Where 'env' is the name of the python virtual environment. 
```
$ python3.6 -m venv env
```

### **Install Dependencies**
To install the dependencies in the virtual environment, you first need to activate it. And insstall all the dependencies from `requirements.txt` file.
```
$ source env/bin/activate
$ pip install -r requirements.txt
```

### **Running**

If you are running the application for the first time, you need to migrate database.

```
$ python manage.py migrate
```

To start the web application, run the following command.
```
$ python manage.py runserver
```

## **Docker Container**

### **Creating Docker Image**
To create docker image, run the following command. This will create docker image and tag it with the provided name and version in the script file.

```
$ sh create_docker_image.sh
```

### **Update Version**

To update the version after each build or new release, you can change the VERSION environment variable inside the script.