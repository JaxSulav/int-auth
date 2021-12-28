import psycopg2

# establishing the connection
# conn = psycopg2.connect(
#     database="invportal", user='invuser', password='password', host='127.0.0.1', port='5432'
# )

# # Setting auto commit false
# conn.autocommit = True

# # Creating a cursor object using the cursor() method
# cursor = conn.cursor()

# # Retrieving data
# cursor.execute('''SELECT * from provider_accesstoken''')

# # Fetching 1st row from the table
# # result = cursor.fetchone();
# # print(result)

# # Fetching 1st row from the table
# result = cursor.fetchall()
# print(result)

# # Commit your changes in the database
# # conn.commit()

# # Closing the connection
# conn.close()


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

