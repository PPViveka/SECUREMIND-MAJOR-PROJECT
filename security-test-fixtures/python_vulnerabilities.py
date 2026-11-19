import os
import pickle
import sqlite3
from flask import request

API_KEY = "demo-secret-key-123456789"


def vulnerable_report():
    user_id = request.args.get("user_id")
    filename = request.args.get("filename")
    command = request.args.get("command")
    query = "SELECT * FROM users WHERE id = " + user_id
    rows = sqlite3.connect("app.db").execute(query).fetchall()
    contents = open(filename).read()
    os.system(command)
    payload = pickle.loads(request.data)
    return {"rows": rows, "contents": contents, "payload": payload}
