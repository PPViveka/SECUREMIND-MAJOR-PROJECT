"""
Benchmark Test Cases: SQL Injection - Vulnerable Patterns (5 cases)
Ground Truth: VULNERABLE
"""

import sqlite3


def get_user_by_id(user_id):
    """Vulnerable: String concatenation directly in execute"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    return cursor.fetchall()


def search_products(keyword):
    """Vulnerable: f-string interpolation directly in SQL statement"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
    cursor.execute(query)
    return cursor.fetchall()


def login_user(username, password):
    """Vulnerable: str.format interpolation directly in SQL statement"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT id, username FROM accounts WHERE user='{}' AND pass='{}'".format(username, password)
    cursor.execute(query)
    return cursor.fetchall()


def delete_order(order_id):
    """Vulnerable: % formatting directly in SQL statement"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "DELETE FROM orders WHERE id = %s" % order_id
    cursor.execute(query)
    conn.commit()
    return True


def filter_records(table, condition):
    """Vulnerable: raw string concatenation with multiple parameters"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT * FROM " + table + " WHERE " + condition
    cursor.execute(query)
    return cursor.fetchall()
