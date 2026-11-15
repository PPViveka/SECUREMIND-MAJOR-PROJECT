"""
Benchmark Test Cases: SQL Injection - Guarded / Benign Patterns (5 cases)
Ground Truth: GUARDED / BENIGN (False Positive Controls)
"""

import sqlite3


def get_user_by_id_safe(user_id):
    """Guarded: Parameterized query placeholder prevents SQLi"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()


def search_products_safe(keyword):
    """Guarded: Parameterized LIKE query prevents SQLi"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{keyword}%",))
    return cursor.fetchall()


def login_user_safe(username, password_hash):
    """Guarded: Parameterized multi-argument query prevents SQLi"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username FROM accounts WHERE user = ? AND pass = ?",
        (username, password_hash),
    )
    return cursor.fetchall()


def delete_order_safe(order_id):
    """Guarded: Integer conversion guard + parameterized query"""
    safe_id = int(order_id)
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM orders WHERE id = ?", (safe_id,))
    conn.commit()
    return True


def filter_by_status_safe(status):
    """Guarded: Strict whitelist guard against untrusted input"""
    allowed_statuses = {"active", "pending", "archived", "suspended"}
    if status not in allowed_statuses:
        raise ValueError("Invalid status filter")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE status = ?", (status,))
    return cursor.fetchall()
