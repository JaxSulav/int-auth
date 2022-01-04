import os
import psycopg2

from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(dotenv_path=os.path.join(BASE_DIR, '.env'))


class SingleInstanceMetaClass(type):
    def __init__(self, name, bases, dic):
        self.__single_instance = None
        super().__init__(name, bases, dic)

    def __call__(cls, *args, **kwargs):
        if cls.__single_instance:
            return cls.__single_instance
        single_obj = cls.__new__(cls)
        single_obj.__init__(*args, **kwargs)
        cls.__single_instance = single_obj
        return single_obj


class Connect(metaclass=SingleInstanceMetaClass):
    def __init__(self):
        self.conn = psycopg2.connect(
            database=os.environ.get("POSTGRES_NAME"),
            user=os.environ.get("POSTGRES_USER"),
            password=os.environ.get('POSTGRES_PASSWORD'),
            host=os.environ.get('POSTGRES_HOST', 'db'),
            port='5432'
        )
        # Setting auto commit false
        self.conn.autocommit = False

