def getDBConnection():
    '''
    Return a MySQL database connection.
    '''
    import os
    import mysql.connector

    password = os.environ.get('MYSQL_PASSWORD', 'password')
    return mysql.connector.connect(user='user', password=password, host='host', database='database')