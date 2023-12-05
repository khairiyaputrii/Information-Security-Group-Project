from flask import Blueprint, render_template, request as flask_request, redirect, url_for, flash, session
from backend.database.db import create_connection

def create_request(source_id, source_username, destination_id):
    connection = create_connection()
    cursor = connection.cursor()

    insert_data_query = """
        INSERT INTO request (
            sourceID,
            sourceUsername,
            destinationID
        ) VALUES (%s, %s, %s)
    """
    data = (source_id, source_username, destination_id)
    cursor.execute(insert_data_query, data)

    connection.commit()
    cursor.close()
    connection.close()

def check_existing_request(source_id, destination_id):
    connection = create_connection()
    cursor = connection.cursor()

    query_check_request = """
        SELECT id
        FROM request
        WHERE sourceID = %s AND destinationID = %s
    """
    cursor.execute(query_check_request, (source_id, destination_id))
    existing_request = cursor.fetchone()

    cursor.close()
    connection.close()

    return existing_request

def fetch_users(user_id):
    connection = create_connection()
    cursor = connection.cursor()

    query = """
        SELECT id, username
        FROM users
        WHERE id != %s
    """
    cursor.execute(query, (user_id,))
    result = cursor.fetchall()

    cursor.close()
    connection.close()

    return result

def fetch_existing_requests(user_id):
    connection = create_connection()
    cursor = connection.cursor()

    query_two = """
        SELECT sourceID, sourceUsername
        FROM request
        WHERE destinationID = %s
    """
    cursor.execute(query_two, (user_id,))
    result = cursor.fetchall()

    cursor.close()
    connection.close()

    return result

def fetch_approved_users(user_id):
    connection = create_connection()
    cursor = connection.cursor()
    query_two = """
        SELECT sourceID, sourceUsername
        FROM request
        WHERE destinationID = %s and cipherText IS NOT NULL
    """
    cursor.execute(query_two, (user_id,))
    result = cursor.fetchall()

    cursor.close()
    connection.close()

    return result