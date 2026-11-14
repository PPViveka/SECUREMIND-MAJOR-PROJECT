from src.sast_scanner import SASTScanner
import json

code = """
import sqlite3
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"""

findings = SASTScanner.scan_code(code)
print(json.dumps(findings, indent=2))
