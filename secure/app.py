"""
VulnNotes — SECURE version. Same app, every flaw fixed.

Each fix is tagged  # FIX: <vuln>  opposite the  # VULN  tag in the
vulnerable build. Runs on http://127.0.0.1:5001 so you can diff behaviour
against the vulnerable one side by side.

Deps: flask, werkzeug (ships with flask). Stdlib otherwise.
"""

import ipaddress
import socket
import sqlite3
import urllib.parse
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (Flask, request, redirect, session, abort,
                   render_template_string)

app = Flask(__name__)
app.secret_key = "change-me-to-a-real-random-32-byte-secret"  # FIX: signed sessions
DB = "vulnnotes_secure.db"

ALLOWED_FETCH_HOSTS = {"example.com", "www.example.com"}  # FIX: SSRF allowlist


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()
    c.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
            password TEXT, role TEXT DEFAULT 'user');
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT,
            body TEXT, private INTEGER DEFAULT 1);
        """
    )
    # FIX: broken-auth — store salted password hashes, never plaintext.
    c.executemany(
        "INSERT INTO users(username,password,role) VALUES(?,?,?)",
        [("alice", generate_password_hash("password123"), "user"),
         ("bob", generate_password_hash("hunter2"), "user"),
         ("admin", generate_password_hash("S3cr3tAdminPass!"), "admin")],
    )
    c.executemany(
        "INSERT INTO notes(owner,title,body,private) VALUES(?,?,?,?)",
        [("alice", "Shopping", "milk, eggs, bread", 1),
         ("alice", "Diary", "alice secret note", 1),
         ("bob", "Todo", "fix the car", 1),
         ("admin", "FLAG", "FLAG{idor_broke_access_control}", 1)],
    )
    c.commit()
    c.close()


# FIX: XSS — autoescape ON (default). Never use |safe on user data.
PAGE = """
<!doctype html><title>VulnNotes (secure)</title>
<h2>VulnNotes (secure)</h2>
<p>user: <b>{{ user or 'anonymous' }}</b> |
<a href="/">home</a> <a href="/login">login</a>
<a href="/search">search</a> <a href="/fetch">url-preview</a></p>
<hr>{{ body }}
"""


def current_user():
    return session.get("user")  # FIX: identity from signed session, not cookie


def render(body_html, user=None):
    # body_html is built from escape()'d pieces below, marked safe explicitly.
    from markupsafe import Markup
    return render_template_string(PAGE, body=Markup(body_html),
                                  user=user or current_user())


@app.route("/")
def home():
    rows = db().execute("SELECT id,owner,title,private FROM notes").fetchall()
    me = current_user()
    items = "".join(
        f'<li><a href="/note/{r["id"]}">#{r["id"]} {escape(r["title"])}</a> '
        f'(owner: {escape(r["owner"])})</li>'
        for r in rows if not r["private"] or r["owner"] == me
    )
    return render(f"<h3>Notes you can see</h3><ul>{items}</ul>")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render('<form method=post>'
                      'user <input name=username> pass '
                      '<input name=password type=password>'
                      '<button>login</button></form>')
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    # FIX: SQLi — parameterized query; input can never alter SQL structure.
    row = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    # FIX: broken-auth — constant-time hash comparison.
    if not row or not check_password_hash(row["password"], p):
        return render("<p>bad credentials</p>")
    session.clear()
    session["user"] = row["username"]
    session["role"] = row["role"]
    return redirect("/")


@app.route("/note/<int:nid>")
def note(nid):
    r = db().execute("SELECT * FROM notes WHERE id=?", (nid,)).fetchone()
    if not r:
        abort(404)
    # FIX: IDOR — enforce ownership before returning a private note.
    if r["private"] and r["owner"] != current_user():
        abort(403)
    # FIX: XSS — all fields escaped.
    return render(f'<h3>{escape(r["title"])}</h3>'
                  f'<p>owner: {escape(r["owner"])}</p>'
                  f'<div>{escape(r["body"])}</div>')


@app.route("/note/new", methods=["GET", "POST"])
def new_note():
    user = current_user()
    if not user:                     # FIX: require auth to create
        abort(401)
    if request.method == "GET":
        return render('<form method=post>title <input name=title><br>'
                      'body <textarea name=body></textarea><br>'
                      '<button>save</button></form>')
    c = db()
    c.execute("INSERT INTO notes(owner,title,body) VALUES(?,?,?)",
              (user, request.form.get("title", ""), request.form.get("body", "")))
    c.commit()
    nid = c.execute("SELECT last_insert_rowid() AS i").fetchone()["i"]
    return redirect(f"/note/{nid}")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # FIX: reflected XSS — escape before echoing.
    body = f"<form>search <input name=q value='{escape(q)}'><button>go</button></form>"
    if q:
        rows = db().execute("SELECT id,title FROM notes WHERE title LIKE ?",
                            (f"%{q}%",)).fetchall()
        hits = "".join(f'<li><a href="/note/{r["id"]}">{escape(r["title"])}</a></li>'
                       for r in rows)
        body += f"<p>results for <b>{escape(q)}</b>:</p><ul>{hits}</ul>"
    return render(body)


def _is_public_host(host):
    # FIX: SSRF — resolve and reject any private/loopback/link-local address.
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast):
                return False
        return True
    except Exception:
        return False


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return render('<form>url <input name=url size=40>'
                      '<button>preview</button></form>')
    p = urllib.parse.urlparse(url)
    # FIX: SSRF — scheme + host allowlist, and block internal IPs.
    if p.scheme not in ("http", "https"):
        abort(400)
    if p.hostname not in ALLOWED_FETCH_HOSTS or not _is_public_host(p.hostname):
        return render("<p>host not allowed</p>")
    import http.client
    conn = (http.client.HTTPSConnection if p.scheme == "https"
            else http.client.HTTPConnection)(p.netloc, timeout=5)
    conn.request("GET", p.path or "/")
    data = conn.getresponse().read(2000).decode("utf-8", "replace")
    return render(f"<h3>preview of {escape(url)}</h3><pre>{escape(data)}</pre>")


@app.route("/admin")
def admin():
    # FIX: access control — role from server-side session, not client input.
    if session.get("role") != "admin":
        abort(403)
    rows = db().execute("SELECT username,role FROM users").fetchall()  # no pw dump
    t = "".join(f"<tr><td>{escape(r['username'])}</td>"
                f"<td>{escape(r['role'])}</td></tr>" for r in rows)
    return render(f"<h3>admin: users</h3><table border=1>"
                  f"<tr><th>user<th>role</tr>{t}</table>")


if __name__ == "__main__":
    init_db()
    print("VulnNotes SECURE on http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
