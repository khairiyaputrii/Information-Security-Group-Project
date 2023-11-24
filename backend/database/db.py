#db.py
import mysql.connector

db_config = {
    "host": "127.0.0.1",
    "user": "root",
    "password": "",
    "database": "informationsecurity",
    "charset": "utf8mb4",
    "connection_timeout": 300,
}

def create_connection():
    return mysql.connector.connect(**db_config)
