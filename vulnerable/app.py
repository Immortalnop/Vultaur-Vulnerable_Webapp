"""
VulnNotes — intentionally vulnerable web app (TRAINING ONLY).

A tiny "notes" web app with real, working instances of:
  SQLi, Stored/Reflected XSS, SSRF, IDOR, Broken Authentication.

Run ONLY on localhost / an isolated VM. Never expose to a network.
Fixed version lives in ../secure/app.py. Each flaw is tagged  # VULN: <name>.
"""

import http.client
import sqlite3
import urllib.parse
from flask import Flask, request, make_response, redirect, render_template_string

app = Flask(__name__)
DB = "vulnnotes.db"


# ---------------------------------------------------------------- DB setup
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
        CREATE TABLE users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE,
            password TEXT, role TEXT DEFAULT 'user');
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY, owner TEXT, title TEXT,
            body TEXT, private INTEGER DEFAULT 1);
        """
    )
    # Passwords stored in plaintext  # VULN: broken-auth (no hashing)
    c.executemany(
        "INSERT INTO users(username,password,role) VALUES(?,?,?)",
        [("alice", "password123", "user"),
         ("bob", "hunter2", "user"),
         ("admin", "S3cr3tAdminPass!", "admin")],
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


# ---------------------------------------------------------------- helpers
PAGE = """
<!doctype html><title>VulnNotes</title>
<h2>VulnNotes</h2>
<p>user: <b>{{ user or 'anonymous' }}</b> |
<a href="/">home</a> <a href="/login">login</a>
<a href="/search">search</a> <a href="/fetch">url-preview</a></p>
<hr>{{ body|safe }}
"""


def current_user():
    # VULN: broken-auth — identity trusted from a plaintext, unsigned cookie.
    # Anyone can set  user=admin  and become admin. No session secret at all.
    return request.cookies.get("user")


def render(body, user=None):
    return render_template_string(PAGE, body=body, user=user or current_user())


# ---------------------------------------------------------------- routes
@app.route("/")
def home():
    user = current_user()
    rows = db().execute("SELECT id,owner,title FROM notes").fetchall()
    items = "".join(
        f'<li><a href="/note/{r["id"]}">#{r["id"]} {r["title"]}</a> '
        f'(owner: {r["owner"]})</li>'
        for r in rows
    )
    return render(f"<h3>All notes</h3><ul>{items}</ul>", user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render(
            '<form method=post>'
            'user <input name=username> pass <input name=password>'
            '<button>login</button></form>'
        )
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    # VULN: SQLi — credentials concatenated straight into the query.
    # Bypass:  username = admin' --   (password ignored)
    q = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
    try:
        row = db().execute(q).fetchone()
    except sqlite3.Error as e:
        return render(f"<p>SQL error: {e}</p><p>query: <code>{q}</code></p>")
    if not row:
        return render("<p>bad credentials</p>")
    resp = make_response(redirect("/"))
    resp.set_cookie("user", row["username"])  # VULN: broken-auth
    return resp


@app.route("/note/<int:nid>")
def note(nid):
    # VULN: IDOR — any note fetched by id, ownership/privacy never checked.
    r = db().execute("SELECT * FROM notes WHERE id=?", (nid,)).fetchone()
    if not r:
        return render("<p>not found</p>")
    # VULN: Stored XSS — note body rendered without escaping (see PAGE |safe).
    return render(
        f'<h3>{r["title"]}</h3><p>owner: {r["owner"]}</p><div>{r["body"]}</div>'
    )


@app.route("/note/new", methods=["GET", "POST"])
def new_note():
    user = current_user() or "anonymous"
    if request.method == "GET":
        return render(
            '<form method=post>title <input name=title><br>'
            'body <textarea name=body></textarea><br>'
            '<button>save</button></form>', user)
    t = request.form.get("title", "")
    b = request.form.get("body", "")  # stored as-is -> Stored XSS sink
    c = db()
    c.execute("INSERT INTO notes(owner,title,body) VALUES(?,?,?)", (user, t, b))
    c.commit()
    nid = c.execute("SELECT last_insert_rowid() AS i").fetchone()["i"]
    return redirect(f"/note/{nid}")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: Reflected XSS — query echoed back unescaped.
    body = f"<form>search <input name=q value='{q}'><button>go</button></form>"
    if q:
        rows = db().execute(
            "SELECT id,title FROM notes WHERE title LIKE ?", (f"%{q}%",)
        ).fetchall()
        hits = "".join(f'<li><a href="/note/{r["id"]}">{r["title"]}</a></li>'
                       for r in rows)
        body += f"<p>results for <b>{q}</b>:</p><ul>{hits}</ul>"
    return render(body)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return render(
            '<form>url <input name=url size=40 '
            'placeholder="http://example.com">'
            '<button>preview</button></form>')
    # VULN: SSRF — server fetches any user-supplied URL with no validation,
    # so it reaches internal hosts (127.0.0.1, 169.254.169.254, intranet).
    try:
        p = urllib.parse.urlparse(url)
        conn = (http.client.HTTPSConnection if p.scheme == "https"
                else http.client.HTTPConnection)(p.netloc, timeout=5)
        conn.request("GET", p.path or "/")
        data = conn.getresponse().read(2000).decode("utf-8", "replace")
    except Exception as e:
        return render(f"<p>fetch error: {e}</p>")
    return render(f"<h3>preview of {url}</h3><pre>{data}</pre>")


@app.route("/admin")
def admin():
    # VULN: broken-auth / broken access control — role read from the cookie,
    # which the client fully controls. Set  user=admin  to walk in.
    if current_user() != "admin":
        return render("<p>403 — admins only</p>")
    rows = db().execute("SELECT username,password,role FROM users").fetchall()
    t = "".join(f"<tr><td>{r['username']}</td><td>{r['password']}</td>"
                f"<td>{r['role']}</td></tr>" for r in rows)
    return render(f"<h3>admin: all users</h3><table border=1>"
                  f"<tr><th>user<th>pass<th>role</tr>{t}</table>")


if __name__ == "__main__":
    init_db()
    print("VulnNotes on http://127.0.0.1:5000  (TRAINING ONLY)")
    app.run(host="127.0.0.1", port=5000, debug=False)
