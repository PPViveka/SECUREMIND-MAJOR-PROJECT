"""
Benchmark Test Cases: SQL Injection - Vulnerable Patterns (10 cases)
Ground Truth: VULNERABLE
"""

import sqlite3


def get_user_by_id(user_id):
    """Vulnerable: String concatenation directly in execute (dev)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    return cursor.fetchall()


def search_products(keyword):
    """Vulnerable: f-string interpolation directly in SQL statement (dev)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
    cursor.execute(query)
    return cursor.fetchall()


def login_user(username, password):
    """Vulnerable: str.format interpolation directly in SQL statement (dev)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT id, username FROM accounts WHERE user='{}' AND pass='{}'".format(username, password)
    cursor.execute(query)
    return cursor.fetchall()


def delete_order(order_id):
    """Vulnerable: % formatting directly in SQL statement (dev)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "DELETE FROM orders WHERE id = %s" % order_id
    cursor.execute(query)
    conn.commit()
    return True


def filter_records(table, condition):
    """Vulnerable: raw string concatenation with multiple parameters (dev)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT * FROM " + table + " WHERE " + condition
    cursor.execute(query)
    return cursor.fetchall()


def find_invoice_by_num(invoice_num):
    """Vulnerable: Dynamic string concat for invoice lookup (eval)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    q = "SELECT total, date FROM invoices WHERE invoice_num = '" + str(invoice_num) + "'"
    cursor.execute(q)
    return cursor.fetchall()


def search_customers_by_email(email_query):
    """Vulnerable: Unescaped email parameter in SELECT (eval)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    sql = f"SELECT id, name FROM customers WHERE email = '{email_query}'"
    cursor.execute(sql)
    return cursor.fetchall()


def update_user_role(role, uid):
    """Vulnerable: Formatting role into UPDATE statement (eval)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("UPDATE members SET role = '%s' WHERE id = %s" % (role, uid))
    conn.commit()
    return True


def fetch_comments_by_post(post_id):
    """Vulnerable: String concatenation in child record query (eval)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM comments WHERE post_id = " + str(post_id))
    return cursor.fetchall()


def report_sales_by_department(dept_name):
    """Vulnerable: format string in aggregation report (eval)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT sum(amount) FROM sales WHERE dept = '{}'".format(dept_name)
    cursor.execute(query)
    return cursor.fetchall()
