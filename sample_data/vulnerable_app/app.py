import os, sys
import sqlite3
from flask import Flask, request
from helpers import clean

app = Flask(__name__)
SECRET_KEY = "super-secret-key-123"
db_password = "hunter2hunter2"

@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("x.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s" % uid)
    return str(cur.fetchall())

@app.route("/run")
def run():
    return str(eval(request.args.get("expr")))

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
