import os
import mysql.connector


def getConnection():
    '''
    Return a connection object for a MySQL database.
    '''
    password = os.environ.get('MYSQL_PASSWORD')
    if not isinstance(password, str) or password == '':
        password = 'password'
    else:
        if any(ch in password for ch in ("\x00", "\n", "\r", "\t", "'", '"', ';', '--', '/*', '*/', '\\')):
            password = 'password'

    return mysql.connector.connect(user='user', password=password, host='host', database='database')