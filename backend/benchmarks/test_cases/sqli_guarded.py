"""
Benchmark Test Cases: SQL Injection - Guarded / Benign Patterns (10 cases)
Ground Truth: GUARDED / BENIGN (False Positive Controls)
"""

import sqlite3


def get_user_by_id_safe(user_id):
    """Guarded: Parameterized query placeholder prevents SQLi (dev)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()


def search_products_safe(keyword):
    """Guarded: Parameterized LIKE query prevents SQLi (dev)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{keyword}%",))
    return cursor.fetchall()


def login_user_safe(username, password_hash):
    """Guarded: Parameterized multi-argument query prevents SQLi (dev)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username FROM accounts WHERE user = ? AND pass = ?",
        (username, password_hash),
    )
    return cursor.fetchall()


def delete_order_safe(order_id):
    """Guarded: Integer conversion guard + parameterized query (dev)"""
    safe_id = int(order_id)
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM orders WHERE id = ?", (safe_id,))
    conn.commit()
    return True


def filter_by_status_safe(status):
    """Guarded: Strict whitelist guard against untrusted input (dev)"""
    allowed_statuses = {"active", "pending", "archived", "suspended"}
    if status not in allowed_statuses:
        raise ValueError("Invalid status filter")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM records WHERE status = ?", (status,))
    return cursor.fetchall()


def find_invoice_by_num_safe(invoice_num):
    """Guarded: Parameterized query for invoice lookup (eval)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT total, date FROM invoices WHERE invoice_num = ?", (str(invoice_num),))
    return cursor.fetchall()


def search_customers_by_email_safe(email_query):
    """Guarded: Bound parameter for customer email search (eval)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM customers WHERE email = ?", (email_query,))
    return cursor.fetchall()


def update_user_role_safe(role, uid):
    """Guarded: Role allowlist check and parameterized UPDATE (eval)"""
    allowed_roles = {"viewer", "editor", "admin"}
    if role not in allowed_roles:
        raise ValueError("Unknown role")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("UPDATE members SET role = ? WHERE id = ?", (role, int(uid)))
    conn.commit()
    return True


def fetch_comments_by_post_safe(post_id):
    """Guarded: Integer conversion and parameter binding (eval)"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM comments WHERE post_id = ?", (int(post_id),))
    return cursor.fetchall()


def report_sales_by_department_safe(dept_name):
    """Guarded: Validated department filter with query param (eval)"""
    valid_depts = {"engineering", "finance", "sales", "hr"}
    if dept_name not in valid_depts:
        raise ValueError("Invalid department")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT sum(amount) FROM sales WHERE dept = ?", (dept_name,))
    return cursor.fetchall()
