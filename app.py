import os
import re
import json
import time
import base64
import sqlite3
import secrets
import threading
import html as html_lib
from email.utils import parseaddr

from flask import Flask, request, jsonify, redirect, Response
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build


# ============================================================
# Local Gmail OTP Backend — v3.1
# - Gmail OAuth (read-only)
# - Scans only the latest 3 inbox messages
# - Checks messages up to 30 seconds old
# - Subject-first OTP extraction
# - Specifically handles: "imo Verification Code: 5043"
# - Never uses a generic-number fallback
# - SSE pushes new OTPs to the frontend
# ============================================================

os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_SECRETS_FILE = os.path.join(BASE_DIR, "credentials.json")
DB_FILE = os.path.join(BASE_DIR, "otp_dashboard.db")

FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://nmbr2.netlify.app").rstrip("/")
REDIRECT_URI = os.environ.get(
    "REDIRECT_URI",
    "http://127.0.0.1:5000/oauth2callback"
)

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

SCAN_INTERVAL = 1
MAX_EMAILS_PER_SCAN = 3
NEW_MAIL_WINDOW = 30
OTP_LIFETIME = 300


CORS(
    app,
    resources={r"/*": {"origins": [FRONTEND_URL]}},
    supports_credentials=True,
)


# ============================================================
# Database
# ============================================================

DB_LOCK = threading.Lock()


def db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with DB_LOCK:
        conn = db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                state TEXT,
                code_verifier TEXT,
                credentials_json TEXT,
                connected INTEGER DEFAULT 0,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS gmail_account (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                credentials_json TEXT,
                connected INTEGER DEFAULT 0,
                updated_at REAL NOT NULL
            )
        """)

        # Migrate an already-connected session into the persistent
        # single-account store. This keeps Gmail connected across
        # browser refreshes and app.py restarts.
        existing = conn.execute(
            "SELECT credentials_json, connected FROM sessions WHERE connected = 1 AND credentials_json IS NOT NULL ORDER BY updated_at DESC LIMIT 1"
        ).fetchone()
        account = conn.execute("SELECT id FROM gmail_account WHERE id = 1").fetchone()
        if not account:
            if existing:
                conn.execute(
                    "INSERT INTO gmail_account(id, credentials_json, connected, updated_at) VALUES (1, ?, 1, ?)",
                    (existing[0], time.time()),
                )
            else:
                conn.execute(
                    "INSERT INTO gmail_account(id, credentials_json, connected, updated_at) VALUES (1, NULL, 0, ?)",
                    (time.time(),),
                )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS seen_messages_v2 (
                session_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                otp TEXT,
                created_at REAL NOT NULL,
                PRIMARY KEY (session_id, message_id)
            )
        """)
        conn.commit()
        conn.close()


init_db()


def create_session():
    sid = secrets.token_urlsafe(24)
    now = time.time()
    with DB_LOCK:
        conn = db()
        account = conn.execute(
            "SELECT credentials_json, connected FROM gmail_account WHERE id = 1"
        ).fetchone()
        account_credentials = account[0] if account else None
        account_connected = int(account[1]) if account else 0
        conn.execute(
            """
            INSERT INTO sessions
            (session_id, state, code_verifier, credentials_json, connected, created_at, updated_at)
            VALUES (?, NULL, NULL, ?, ?, ?, ?)
            """,
            (sid, account_credentials, account_connected, now, now),
        )
        conn.commit()
        conn.close()
    return sid


def get_session(session_id):
    if not session_id:
        return None
    with DB_LOCK:
        conn = db()
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        conn.close()
    return row


def update_session(session_id, **fields):
    if not fields:
        return
    fields["updated_at"] = time.time()
    columns = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [session_id]

    with DB_LOCK:
        conn = db()
        conn.execute(
            f"UPDATE sessions SET {columns} WHERE session_id = ?",
            values,
        )
        conn.commit()
        conn.close()


# ============================================================
# SSE
# ============================================================

SSE_CLIENTS = {}
SSE_LOCK = threading.Lock()


def sse_add(session_id):
    q = []
    with SSE_LOCK:
        SSE_CLIENTS.setdefault(session_id, []).append(q)
    return q


def sse_remove(session_id, q):
    with SSE_LOCK:
        clients = SSE_CLIENTS.get(session_id, [])
        if q in clients:
            clients.remove(q)
        if not clients:
            SSE_CLIENTS.pop(session_id, None)


def sse_push(session_id, event_name, payload):
    data = json.dumps(payload, ensure_ascii=False)
    message = f"event: {event_name}\ndata: {data}\n\n"

    with SSE_LOCK:
        clients = list(SSE_CLIENTS.get(session_id, []))

    for q in clients:
        q.append(message)


# ============================================================
# OTP validation / extraction
# ============================================================

OTP_DIGITS_RE = re.compile(r"(?<!\d)(\d{4,8})(?!\d)")


def clean_text(value):
    if not value:
        return ""
    value = html_lib.unescape(value)
    value = re.sub(r"<br\s*/?>", "\n", value, flags=re.I)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def is_valid_otp(code, allow_repeated=False):
    if code is None:
        return False

    code = str(code).strip()

    if not re.fullmatch(r"\d{4,8}", code):
        return False

    # Repeated values such as 111111 / 999999 are normally
    # placeholders. They are allowed only when a strong
    # OTP/code phrase explicitly identifies them.
    if not allow_repeated and len(set(code)) == 1:
        return False

    # Four-digit years should not be treated as OTPs.
    if len(code) == 4 and re.fullmatch(r"(19|20)\d{2}", code):
        return False

    return True


def _first_number(pattern, text, allow_repeated=False):
    match = re.search(pattern, text, flags=re.I)
    if not match:
        return None

    code = match.group(1)
    if is_valid_otp(code, allow_repeated=allow_repeated):
        return code

    return None


def extract_otp(subject="", body="", snippet=""):
    """
    IMPORTANT:
    Subject is checked BEFORE body/snippet.

    This fixes emails such as:
        Subject: "imo Verification Code: 5043"
        Body:    "... 000000 ..."

    Result:
        5043

    There is intentionally NO generic "any 4-8 digit number"
    fallback. If a number is not clearly associated with an
    OTP/code phrase, it is not returned.
    """

    subject = clean_text(subject)
    body = clean_text(body)
    snippet = clean_text(snippet)

    # --------------------------------------------------------
    # 1) SUBJECT — highest priority
    # --------------------------------------------------------

    subject_patterns = [
        # imo / generic verification-code formats
        r"\bverification\s+code(?:\s+is|\s*[:\-])\s*(\d{4,8})\b",
        r"\bverification\s+(?:number|no\.?|#)(?:\s*[:\-]|\s+is\s+)(\d{4,8})\b",
        r"\b(?:one[-\s]?time|security|login|confirmation|authentication|access)\s+code(?:\s+is|\s*[:\-])\s*(\d{4,8})\b",
        r"\b(?:otp|passcode|pin)(?:\s*[:\-]|\s+is\s+)(\d{4,8})\b",

        # "Your code is 123456", "Code: 123456"
        r"\b(?:your\s+)?(?:verification\s+)?code(?:\s+is|\s*[:\-])\s*(\d{4,8})\b",

        # Explicit CODE-123456 / OTP-123456
        r"\b(?:otp|code)[_\-\s]*(\d{4,8})\b",
    ]

    for pattern in subject_patterns:
        # Subject is explicit code context, so repeated values
        # are accepted if the subject itself says they are the code.
        code = _first_number(pattern, subject, allow_repeated=True)
        if code:
            return code

    # --------------------------------------------------------
    # 2) BODY — only strong OTP/code context
    # --------------------------------------------------------

    body_patterns = [
        r"\bverification\s+code(?:\s+is|\s*[:\-])\s*(\d{4,8})\b",
        r"\bverification\s+(?:number|no\.?|#)(?:\s*[:\-]|\s+is\s+)(\d{4,8})\b",
        r"\b(?:one[-\s]?time|security|login|confirmation|authentication|access)\s+code(?:\s+is|\s*[:\-])\s*(\d{4,8})\b",
        r"\b(?:otp|passcode|pin)(?:\s*[:\-]|\s+is\s+)(\d{4,8})\b",
        r"\b(?:your\s+)?(?:verification\s+)?code(?:\s+is|\s*[:\-])\s*(\d{4,8})\b",
        r"\b(?:otp|code)[_\-\s]*(\d{4,8})\b",
    ]

    for pattern in body_patterns:
        code = _first_number(pattern, body, allow_repeated=False)
        if code:
            return code

    # --------------------------------------------------------
    # 3) SNIPPET — same strict rules
    # --------------------------------------------------------

    for pattern in body_patterns:
        code = _first_number(pattern, snippet, allow_repeated=False)
        if code:
            return code

    # No clearly identified OTP => show nothing.
    return None


# ============================================================
# Gmail helpers
# ============================================================

def credentials_from_session(row):
    if not row:
        return None

    raw = row["credentials_json"] if row["credentials_json"] else None

    # If the browser session was created before the persistent account
    # was introduced, load the saved Gmail credentials from gmail_account.
    if not raw:
        with DB_LOCK:
            conn = db()
            account = conn.execute(
                "SELECT credentials_json FROM gmail_account WHERE id = 1 AND connected = 1"
            ).fetchone()
            conn.close()
        if account:
            raw = account[0]
            if raw:
                update_session(row["session_id"], credentials_json=raw, connected=1)

    if not raw:
        return None

    try:
        creds = Credentials.from_authorized_user_info(
            json.loads(raw),
            SCOPES,
        )

        # Access tokens expire. The refresh token is persisted in the
        # OAuth credential JSON, so refresh silently without another login.
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            refreshed = creds.to_json()
            update_session(row["session_id"], credentials_json=refreshed, connected=1)
            with DB_LOCK:
                conn = db()
                conn.execute(
                    "UPDATE gmail_account SET credentials_json = ?, connected = 1, updated_at = ? WHERE id = 1",
                    (refreshed, time.time()),
                )
                conn.commit()
                conn.close()

        return creds
    except Exception as exc:
        print("[CREDENTIAL ERROR]", repr(exc))
        return None


def gmail_service_for_session(row):
    creds = credentials_from_session(row)
    if not creds or (not creds.valid and not creds.refresh_token):
        return None

    try:
        return build(
            "gmail",
            "v1",
            credentials=creds,
            cache_discovery=False,
        )
    except Exception as exc:
        print("[GMAIL SERVICE ERROR]", repr(exc))
        return None


def decode_base64url(data):
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode(
            "utf-8",
            errors="ignore",
        )
    except Exception:
        return ""


def extract_message_text(payload):
    plain_parts = []
    html_parts = []

    def walk(part):
        if not part:
            return

        mime = (part.get("mimeType") or "").lower()
        body_data = (part.get("body") or {}).get("data")

        if body_data:
            decoded = decode_base64url(body_data)
            if "text/plain" in mime:
                plain_parts.append(decoded)
            elif "text/html" in mime:
                html_parts.append(decoded)

        for child in part.get("parts") or []:
            walk(child)

    walk(payload)

    plain = "\n".join(plain_parts)
    html_text = "\n".join(html_parts)

    return clean_text(plain), clean_text(html_text)


def header_value(headers, name):
    for h in headers or []:
        if (h.get("name") or "").lower() == name.lower():
            return h.get("value") or ""
    return ""


def sender_display(from_header):
    name, email_addr = parseaddr(from_header or "")
    if name:
        return name.strip(), email_addr.strip()
    return email_addr.strip() or "Unknown", email_addr.strip()


def remember_seen(session_id, message_id, otp):
    with DB_LOCK:
        conn = db()
        row = conn.execute(
            "SELECT message_id FROM seen_messages_v2 WHERE session_id = ? AND message_id = ?",
            (session_id, message_id),
        ).fetchone()

        if row:
            conn.close()
            return False

        conn.execute(
            "INSERT INTO seen_messages_v2(session_id, message_id, otp, created_at) VALUES (?, ?, ?, ?)",
            (session_id, message_id, otp, time.time()),
        )

        # Keep the table small.
        cutoff = time.time() - 86400
        conn.execute(
            "DELETE FROM seen_messages_v2 WHERE created_at < ?",
            (cutoff,),
        )

        conn.commit()
        conn.close()

    return True


# ============================================================
# Active OTP state
# ============================================================

ACTIVE_OTPS = {}
ACTIVE_LOCK = threading.Lock()


def active_otps_for_session(session_id):
    now = time.time()

    with ACTIVE_LOCK:
        items = ACTIVE_OTPS.get(session_id, {})
        expired_ids = [
            k for k, v in items.items()
            if v.get("expires_at", 0) <= now
        ]

        for k in expired_ids:
            item = items.pop(k)
            sse_push(
                session_id,
                "otp_expired",
                {"id": item["id"]},
            )

        return sorted(
            list(items.values()),
            key=lambda x: x.get("created_at", 0),
            reverse=True,
        )


def add_active_otp(session_id, item):
    with ACTIVE_LOCK:
        ACTIVE_OTPS.setdefault(session_id, {})[item["id"]] = item


# ============================================================
# Scanner
# ============================================================

def scan_session(session_id):
    row = get_session(session_id)
    if not row:
        return 0

    service = gmail_service_for_session(row)
    if not service:
        return 0

    processed = 0

    try:
        result = (
            service.users()
            .messages()
            .list(
                userId="me",
                labelIds=["INBOX"],
                maxResults=MAX_EMAILS_PER_SCAN,
            )
            .execute()
        )

        messages = result.get("messages") or []

        for msg_ref in messages[:MAX_EMAILS_PER_SCAN]:
            message_id = msg_ref.get("id")
            if not message_id:
                continue

            try:
                detail = (
                    service.users()
                    .messages()
                    .get(
                        userId="me",
                        id=message_id,
                        format="full",
                    )
                    .execute()
                )
            except Exception as exc:
                print("[GMAIL MESSAGE ERROR]", repr(exc))
                continue

            internal_ms = int(detail.get("internalDate") or 0)
            created_at = internal_ms / 1000 if internal_ms else time.time()

            # Ignore old mail. The newest 3 are still checked,
            # but only recent messages can become new OTPs.
            if time.time() - created_at > NEW_MAIL_WINDOW:
                continue

            headers = detail.get("payload", {}).get("headers", [])
            subject = header_value(headers, "Subject")
            from_header = header_value(headers, "From")

            sender, sender_email = sender_display(from_header)

            plain, html_text = extract_message_text(
                detail.get("payload") or {}
            )

            snippet = detail.get("snippet") or ""

            # SUBJECT FIRST — critical for imo:
            # "imo Verification Code: 5043"
            otp = extract_otp(
                subject=subject,
                body=plain or html_text,
                snippet=snippet,
            )

            if not otp:
                # Do not display a code if detection is uncertain.
                continue

            if not remember_seen(session_id, message_id, otp):
                continue

            expires_at = time.time() + OTP_LIFETIME

            item = {
                "id": message_id,
                "otp": otp,
                "sender": sender,
                "sender_email": sender_email,
                "subject": subject or "(No Subject)",
                "created_at": time.time(),
                "expires_at": expires_at,
            }

            add_active_otp(session_id, item)
            sse_push(session_id, "new_otp", item)

            print("[NEW OTP]", item)
            processed += 1

    except Exception as exc:
        print("[SCANNER ERROR]", repr(exc))

    return processed


def scanner_loop():
    print("[SCANNER] Started")
    while True:
        try:
            with DB_LOCK:
                conn = db()
                rows = conn.execute(
                    "SELECT session_id FROM sessions WHERE connected = 1"
                ).fetchall()
                conn.close()

            for row in rows:
                scan_session(row["session_id"])

            # Cleanup expired OTPs.
            session_ids = set()
            with ACTIVE_LOCK:
                session_ids = list(ACTIVE_OTPS.keys())

            for sid in session_ids:
                active_otps_for_session(sid)

        except Exception as exc:
            print("[SCANNER LOOP ERROR]", repr(exc))

        time.sleep(SCAN_INTERVAL)


threading.Thread(target=scanner_loop, daemon=True).start()


# ============================================================
# Routes
# ============================================================

@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "local-gmail-otp-backend",
    })


@app.post("/api/session")
def api_session():
    sid = create_session()
    return jsonify({"session_id": sid})


@app.get("/api/session/ensure")
def api_session_ensure():
    sid = request.args.get("session_id")
    if not sid or not get_session(sid):
        sid = create_session()
    return jsonify({"ok": True, "session_id": sid})


@app.get("/api/status")
def api_status():
    sid = request.args.get("session_id")
    row = get_session(sid)

    if not row:
        return jsonify({
            "status": "ok",
            "gmail_connected": False,
            "active_otps": 0,
            "processed_messages": 0,
            "sse_clients": 0,
        })

    # Persistent Gmail state is authoritative across restarts.
    with DB_LOCK:
        conn = db()
        account = conn.execute(
            "SELECT connected FROM gmail_account WHERE id = 1"
        ).fetchone()
        conn.close()
    account_connected = bool(account and account[0])
    if account_connected and not row["connected"]:
        with DB_LOCK:
            conn = db()
            saved = conn.execute(
                "SELECT credentials_json FROM gmail_account WHERE id = 1"
            ).fetchone()
            conn.close()
        if saved and saved[0]:
            update_session(sid, credentials_json=saved[0], connected=1)
            row = get_session(sid)

    active = active_otps_for_session(sid)

    with SSE_LOCK:
        sse_count = len(SSE_CLIENTS.get(sid, []))

    return jsonify({
        "status": "ok",
        "gmail_connected": bool(row["connected"]),
        "active_otps": len(active),
        "processed_messages": len(active),
        "sse_clients": sse_count,
    })


@app.get("/api/otps")
def api_otps():
    sid = request.args.get("session_id")
    row = get_session(sid)

    if not row:
        return jsonify({
            "connected": False,
            "otps": [],
        })

    return jsonify({
        "connected": bool(row["connected"]),
        "otps": active_otps_for_session(sid),
    })


@app.get("/login")
def login():
    # Self-heal stale browser session IDs. If the browser kept an old
    # session_id after a DB/session reset, silently create a fresh session
    # and continue with Google OAuth instead of returning "Invalid session".
    sid = request.args.get("session_id")
    row = get_session(sid)

    if not row:
        sid = create_session()
        row = get_session(sid)
        print("[SESSION] Replaced stale session with:", sid)

    if not os.path.exists(CLIENT_SECRETS_FILE):
        return (
            "credentials.json not found. Put credentials.json beside app.py.",
            500,
        )

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
    )
    flow.redirect_uri = REDIRECT_URI

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    update_session(
        sid,
        state=state,
        code_verifier=flow.code_verifier,
    )

    return redirect(authorization_url)


@app.get("/oauth2callback")
def oauth2callback():
    sid = request.args.get("state")

    # State itself is stored in DB, so find the matching session.
    with DB_LOCK:
        conn = db()
        row = conn.execute(
            "SELECT * FROM sessions WHERE state = ?",
            (sid,),
        ).fetchone()
        conn.close()

    if not row:
        # Some Google callbacks can be routed without preserving
        # our session query parameter. Fall back to a state lookup
        # using the state parameter from the callback.
        callback_state = request.args.get("state")
        with DB_LOCK:
            conn = db()
            row = conn.execute(
                "SELECT * FROM sessions WHERE state = ?",
                (callback_state,),
            ).fetchone()
            conn.close()

    if not row:
        return "Invalid OAuth state/session", 400

    session_id = row["session_id"]
    code_verifier = row["code_verifier"]

    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=row["state"],
        )
        flow.redirect_uri = REDIRECT_URI

        # Required for OAuth PKCE.
        flow.code_verifier = code_verifier

        flow.fetch_token(
            authorization_response=request.url
        )

        credentials = flow.credentials

        credentials_json = credentials.to_json()

        update_session(
            session_id,
            credentials_json=credentials_json,
            connected=1,
            state=None,
            code_verifier=None,
        )

        # Persist the Gmail OAuth refresh token independently of the
        # browser session. This is what survives app.py restarts.
        with DB_LOCK:
            conn = db()
            conn.execute(
                "UPDATE gmail_account SET credentials_json = ?, connected = 1, updated_at = ? WHERE id = 1",
                (credentials_json, time.time()),
            )
            # Restore the persistent credentials to all existing sessions.
            conn.execute(
                "UPDATE sessions SET credentials_json = ?, connected = 1, updated_at = ?",
                (credentials_json, time.time()),
            )
            conn.commit()
            conn.close()

        print("[OAUTH] Gmail connected and persisted")

        return redirect(
            f"{FRONTEND_URL}/?gmail_connected=1&session_id={session_id}"
        )

    except Exception as exc:
        print("[OAUTH ERROR]", repr(exc))
        return f"OAuth failed: {exc}", 500


@app.post("/api/logout")
def api_logout():
    data = request.get_json(silent=True) or {}
    sid = data.get("session_id")

    row = get_session(sid)
    if not row:
        return jsonify({"ok": True})

    update_session(
        sid,
        credentials_json=None,
        connected=0,
        state=None,
        code_verifier=None,
    )

    # Manual Logout intentionally disconnects the persistent Gmail account.
    with DB_LOCK:
        conn = db()
        conn.execute(
            "UPDATE gmail_account SET credentials_json = NULL, connected = 0, updated_at = ? WHERE id = 1",
            (time.time(),),
        )
        conn.execute(
            "UPDATE sessions SET credentials_json = NULL, connected = 0, updated_at = ?",
            (time.time(),),
        )
        conn.commit()
        conn.close()

    with ACTIVE_LOCK:
        ACTIVE_OTPS.pop(sid, None)

    with SSE_LOCK:
        clients = list(SSE_CLIENTS.pop(sid, []))
        for q in clients:
            q.append(
                "event: logged_out\ndata: {}\n\n"
            )

    print("[LOGOUT] Session:", sid)

    return jsonify({"ok": True})


@app.get("/events")
def events():
    sid = request.args.get("session_id")
    row = get_session(sid)

    if not row:
        return Response(
            "event: error\ndata: {\"error\":\"Invalid session\"}\n\n",
            status=400,
            mimetype="text/event-stream",
        )

    q = sse_add(sid)

    def generate():
        try:
            yield (
                "event: connected\n"
                "data: {\"status\":\"connected\"}\n\n"
            )

            # Send currently active OTPs immediately after connecting.
            for item in active_otps_for_session(sid):
                yield (
                    "event: new_otp\n"
                    f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
                )

            while True:
                if q:
                    message = q.pop(0)
                    yield message
                else:
                    # Keep the SSE connection alive.
                    yield ": keepalive\n\n"

                time.sleep(1)

        except GeneratorExit:
            pass
        finally:
            sse_remove(sid, q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("LOCAL GMAIL OTP BACKEND v3.1")
    print("=" * 60)
    print("Frontend:", FRONTEND_URL)
    print("OAuth redirect:", REDIRECT_URI)
    print("Database:", DB_FILE)
    print("Persistent Gmail account: ENABLED")
    print("Scanning latest:", MAX_EMAILS_PER_SCAN, "Inbox messages")
    print("New-mail window:", NEW_MAIL_WINDOW, "seconds")
    print("OTP lifetime:", OTP_LIFETIME, "seconds")
    print("=" * 60)
    print("Open: http://127.0.0.1:5000/health")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True,
    )
