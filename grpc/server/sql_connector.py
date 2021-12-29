import psycopg2

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
            database="invportal", user='invuser', password='password', host='127.0.0.1', port='5432'
        )
        # Setting auto commit false
        self.conn.autocommit = False

