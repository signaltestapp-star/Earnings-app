import os
import sqlite3
import uuid
from decimal import Decimal, ROUND_DOWN, InvalidOperation
from functools import wraps
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, g, render_template, send_from_directory
import jwt  # PyJWT

DB_PATH = os.environ.get("WALLET_DB", "wallets.db")
JWT_SECRET = os.environ.get("WALLET_JWT_SECRET", "change-me-jwt-secret")
JWT_ALGO = "HS256"
ADMIN_USERNAME = os.environ.get("WALLET_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("WALLET_ADMIN_PASS", "adminpass")  # change in production

app = Flask(__name__, static_folder="static", template_folder="templates")


# ---------- DB helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS wallets (
        id TEXT PRIMARY KEY,
        secret TEXT NOT NULL,
        label TEXT,
        balance TEXT NOT NULL
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS txs (
        id TEXT PRIMARY KEY,
        wallet_from TEXT,
        wallet_to TEXT,
        amount TEXT NOT NULL,
        kind TEXT NOT NULL,
        note TEXT,
        created_at DATETIME DEFAULT (datetime('now'))
    );
    """)
    db.commit()
    db.close()

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------- utilities ----------
def normalize_amount(value):
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError("Invalid amount format")
    return d.quantize(Decimal("0.01"), rounding=ROUND_DOWN)

def require_wallet_secret(f):
    @wraps(f)
    def wrapper(wallet_id, *args, **kwargs):
        secret = request.headers.get("X-WALLET-SECRET")
        if not secret:
            return jsonify({"error": "X-WALLET-SECRET header required"}), 401
        db = get_db()
        r = db.execute("SELECT secret FROM wallets WHERE id = ?", (wallet_id,)).fetchone()
        if not r or r["secret"] != secret:
            return jsonify({"error": "invalid wallet id or secret"}), 403
        return f(wallet_id, *args, **kwargs)
    return wrapper

def require_jwt_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
        if not token:
            return jsonify({"error": "missing admin token"}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            if payload.get("role") != "admin":
                return jsonify({"error": "forbidden"}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except Exception as e:
            return jsonify({"error": "invalid token"}), 401
        return f(*args, **kwargs)
    return wrapper


# ---------- Auth endpoints (admin) ----------
@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}
    user = data.get("username")
    pwd = data.get("password")
    if user != ADMIN_USERNAME or pwd != ADMIN_PASSWORD:
        return jsonify({"error": "invalid credentials"}), 401
    # issue JWT for admin (short lived)
    payload = {
        "sub": ADMIN_USERNAME,
        "role": "admin",
        "exp": datetime.utcnow() + timedelta(hours=6)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    return jsonify({"access_token": token})

# ---------- API endpoints ----------
@app.route("/", methods=["GET"])
def ui_index():
    #serve the SPA
    return render_template("index.html")

@app.route("/api/wallet", methods=["POST"])
def create_wallet():
    data = request.get_json(silent=True) or {}
    label = data.get("label")
    initial = data.get("initial_deposit", "0")
    try:
        amount = normalize_amount(initial)
    except ValueError:
        return jsonify({"error": "invalid initial_deposit"}), 400

    wid = str(uuid.uuid4())
    secret = str(uuid.uuid4())
    db = get_db()
    db.execute("INSERT INTO wallets (id, secret, label, balance) VALUES (?,?,?,?)",
               (wid, secret, label, str(amount)))
    if amount > 0:
        txid = str(uuid.uuid4())
        db.execute("INSERT INTO txs (id, wallet_from, wallet_to, amount, kind, note) VALUES (?,?,?,?,?,?)",
                   (txid, None, wid, str(amount), "deposit", "initial_deposit"))
    db.commit()
    return jsonify({"id": wid, "secret": secret, "label": label, "balance": str(amount)}), 201

@app.route("/api/wallet/<wallet_id>", methods=["GET"])
def get_wallet(wallet_id):
    db = get_db()
    r = db.execute("SELECT id,label,balance FROM wallets WHERE id = ?", (wallet_id,)).fetchone()
    if not r:
        return jsonify({"error": "wallet not found"}), 404
    return jsonify({"id": r["id"], "label": r["label"], "balance": r["balance"]})

@app.route("/api/wallet/<wallet_id>/deposit", methods=["POST"])
def deposit(wallet_id):
    data = request.get_json(silent=True) or {}
    try:
        amount = normalize_amount(data.get("amount", "0"))
    except ValueError:
        return jsonify({"error": "invalid amount"}), 400
    if amount <= 0:
        return jsonify({"error": "amount must be > 0"}), 400

    db = get_db()
    r = db.execute("SELECT balance FROM wallets WHERE id = ?", (wallet_id,)).fetchone()
    if not r:
        return jsonify({"error": "wallet not found"}), 404
    new_balance = normalize_amount(Decimal(r["balance"]) + amount)
    db.execute("UPDATE wallets SET balance = ? WHERE id = ?", (str(new_balance), wallet_id))
    txid = str(uuid.uuid4())
    db.execute("INSERT INTO txs (id, wallet_from, wallet_to, amount, kind, note) VALUES (?,?,?,?,?,?)",
               (txid, None, wallet_id, str(amount), "deposit", data.get("note")))
    db.commit()
    return jsonify({"id": wallet_id, "new_balance": str(new_balance), "tx_id": txid})

@app.route("/api/wallet/<wallet_id>/withdraw", methods=["POST"])
@require_wallet_secret
def withdraw(wallet_id):
    data = request.get_json(silent=True) or {}
    try:
        amount = normalize_amount(data.get("amount", "0"))
    except ValueError:
        return jsonify({"error": "invalid amount"}), 400
    if amount <= 0:
        return jsonify({"error": "amount must be > 0"}), 400

    db = get_db()
    r = db.execute("SELECT balance FROM wallets WHERE id = ?", (wallet_id,)).fetchone()
    if not r:
        return jsonify({"error": "wallet not found"}), 404
    balance = Decimal(r["balance"])
    if amount > balance:
        return jsonify({"error": "insufficient funds"}), 400
    new_balance = normalize_amount(balance - amount)
    db.execute("UPDATE wallets SET balance = ? WHERE id = ?", (str(new_balance), wallet_id))
    txid = str(uuid.uuid4())
    db.execute("INSERT INTO txs (id, wallet_from, wallet_to, amount, kind, note) VALUES (?,?,?,?,?,?)",
               (txid, wallet_id, None, str(amount), "withdraw", data.get("note")))
    db.commit()
    return jsonify({"id": wallet_id, "new_balance": str(new_balance), "tx_id": txid})

@app.route("/api/transfer", methods=["POST"])
def transfer():
    data = request.get_json(silent=True) or {}
    from_id = data.get("from_id")
    to_id = data.get("to_id")
    if not from_id or not to_id:
        return jsonify({"error": "from_id and to_id required"}), 400
    secret = request.headers.get("X-WALLET-SECRET")
    if not secret:
        return jsonify({"error": "X-WALLET-SECRET header required"}), 401
    db = get_db()
    r = db.execute("SELECT secret FROM wallets WHERE id = ?", (from_id,)).fetchone()
    if not r or r["secret"] != secret:
        return jsonify({"error": "invalid wallet id or secret"}), 403
    try:
        amount = normalize_amount(data.get("amount", "0"))
    except ValueError:
        return jsonify({"error": "invalid amount"}), 400
    if amount <= 0:
        return jsonify({"error": "amount must be > 0"}), 400

    cur = db.cursor()
    cur.execute("SELECT balance FROM wallets WHERE id = ?", (from_id,))
    row_from = cur.fetchone()
    cur.execute("SELECT balance FROM wallets WHERE id = ?", (to_id,))
    row_to = cur.fetchone()
    if not row_from or not row_to:
        return jsonify({"error": "from_id or to_id not found"}), 404

    bal_from = Decimal(row_from["balance"])
    bal_to = Decimal(row_to["balance"])
    if amount > bal_from:
        return jsonify({"error": "insufficient funds"}), 400
    bal_from_new = normalize_amount(bal_from - amount)
    bal_to_new = normalize_amount(bal_to + amount)

    cur.execute("UPDATE wallets SET balance = ? WHERE id = ?", (str(bal_from_new), from_id))
    cur.execute("UPDATE wallets SET balance = ? WHERE id = ?", (str(bal_to_new), to_id))
    txid = str(uuid.uuid4())
    cur.execute("INSERT INTO txs (id, wallet_from, wallet_to, amount, kind, note) VALUES (?,?,?,?,?,?)",
                (txid, from_id, to_id, str(amount), "transfer", data.get("note")))
    db.commit()
    return jsonify({
        "tx_id": txid,
        "from": {"id": from_id, "new_balance": str(bal_from_new)},
        "to": {"id": to_id, "new_balance": str(bal_to_new)}
    })

@app.route("/api/admin/edit_balance", methods=["POST"])
@require_jwt_admin
def admin_edit_balance():
    data = request.get_json(silent=True) or {}
    wid = data.get("wallet_id")
    if not wid:
        return jsonify({"error": "wallet_id required"}), 400
    try:
        new_balance = normalize_amount(data.get("new_balance", "0"))
    except ValueError:
        return jsonify({"error": "invalid new_balance"}), 400
    db = get_db()
    r = db.execute("SELECT balance FROM wallets WHERE id = ?", (wid,)).fetchone()
    if not r:
        return jsonify({"error": "wallet not found"}), 404
    db.execute("UPDATE wallets SET balance = ? WHERE id = ?", (str(new_balance), wid))
    txid = str(uuid.uuid4())
    db.execute("INSERT INTO txs (id, wallet_from, wallet_to, amount, kind, note) VALUES (?,?,?,?,?,?)",
               (txid, None, wid, str(new_balance), "admin_edit", data.get("note")))
    db.commit()
    return jsonify({"wallet_id": wid, "new_balance": str(new_balance), "tx_id": txid})

@app.route("/api/txs/<wallet_id>", methods=["GET"])
def list_txs(wallet_id):
    db = get_db()
    rows = db.execute(
        "SELECT id,wallet_from,wallet_to,amount,kind,note,created_at FROM txs WHERE wallet_from = ? OR wallet_to = ? ORDER BY created_at DESC LIMIT 100",
        (wallet_id, wallet_id)).fetchall()
    out = [dict(r) for r in rows]
    return jsonify({"txs": out})

# static files route for JS (if any)
@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
