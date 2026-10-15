"""Intentionally vulnerable demo for SQL injection. Do not use in production."""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("demo.db")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    return conn


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    # VULNERABLE: user input is concatenated directly into the SQL query.
    # Try: /user?username=' OR '1'='1
    query = "SELECT id, username FROM users WHERE username = '" + username + "'"
    rows = conn.execute(query).fetchall()
    return {"users": rows}


def get_user_safe(conn, username):
    # Fixed version: parameterized query.
    return conn.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchall()


if __name__ == "__main__":
    app.run(debug=True)
