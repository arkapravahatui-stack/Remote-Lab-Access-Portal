"""Local FastAPI + SSH lab portal.

Run `python main.py setup` once, then `python main.py`.
This app intentionally listens on localhost only; do not expose it to the internet.
"""

import argparse
import asyncio
import getpass
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncssh
import bcrypt
import jwt
import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
DATABASE_NAME = BASE_DIR / "users.db"
INDEX_FILE = BASE_DIR / "index.html"
AUDIT_LOG_FILE = BASE_DIR / "audit.log"
SECRET_FILE = BASE_DIR / ".portal_secret"
ZERO_HASH = "0" * 64
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 30
IDLE_TIMEOUT_SECONDS = 10
DEFAULT_BANDWIDTH_LIMIT = 100 * 1024 * 1024  # 100 MiB

# These default to the account and SSH key of whoever is running this app.
# Override using environment variables if the SSH account is different.
SSH_HOST = os.environ.get("LAB_SSH_HOST", "localhost")
SSH_USERNAME = os.environ.get("LAB_SSH_USER", getpass.getuser())
SSH_KEY = Path(os.environ.get("LAB_SSH_KEY", str(Path.home() / ".ssh" / "id_ed25519")))

_audit_lock = threading.Lock()
audit_logger = logging.getLogger("remote_lab_audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False
if not audit_logger.handlers:
    handler = logging.FileHandler(AUDIT_LOG_FILE, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(handler)


def load_secret() -> str:
    """Persist a random JWT signing key locally; never use a public default."""
    configured = os.environ.get("LAB_JWT_SECRET")
    if configured:
        if len(configured) < 32:
            raise RuntimeError("LAB_JWT_SECRET must contain at least 32 characters")
        return configured
    if SECRET_FILE.exists():
        existing = SECRET_FILE.read_text(encoding="utf-8").strip()
        if len(existing) < 32:
            raise RuntimeError(f"JWT secret file is invalid: {SECRET_FILE}")
        return existing
    generated = secrets.token_urlsafe(48)
    # Windows file ACLs are inherited from the parent folder. Do not share this file.
    with SECRET_FILE.open("x", encoding="utf-8") as f:
        f.write(generated + "\n")
    try:
        SECRET_FILE.chmod(0o600)
    except OSError:
        pass
    return generated


JWT_SECRET = load_secret()


def init_db() -> None:
    """Create the expected users table without replacing an existing database."""
    with sqlite3.connect(DATABASE_NAME, timeout=15) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                bandwidth_used INTEGER NOT NULL DEFAULT 0,
                bandwidth_limit INTEGER NOT NULL DEFAULT 104857600
            )
        """)


def user_exists(username: str) -> bool:
    with sqlite3.connect(DATABASE_NAME, timeout=15) as conn:
        return conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone() is not None


def user_count() -> int:
    with sqlite3.connect(DATABASE_NAME, timeout=15) as conn:
        return conn.execute("SELECT count(*) FROM users").fetchone()[0]


def create_user(username: str, password: str) -> None:
    username = username.strip()
    if not username or len(username) > 100:
        raise ValueError("Username must have between 1 and 100 characters")
    raw_password = password.encode("utf-8")
    if len(raw_password) < 8 or len(raw_password) > 72:
        raise ValueError("Password must be 8 to 72 bytes long")
    hashed = bcrypt.hashpw(raw_password, bcrypt.gensalt(rounds=12)).decode("ascii")
    with sqlite3.connect(DATABASE_NAME, timeout=15) as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, bandwidth_used, bandwidth_limit) "
            "VALUES (?, ?, 0, ?)",
            (username, hashed, DEFAULT_BANDWIDTH_LIMIT),
        )


def verify_user(username: str, password: str) -> bool:
    with sqlite3.connect(DATABASE_NAME, timeout=15) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    if not row:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), row[0].encode("ascii"))
    except (ValueError, TypeError, UnicodeError):
        return False


def check_quota(username: str, data_bytes: int) -> bool:
    """Atomically charge usage. Return True when unknown/exhausted (fail closed)."""
    if data_bytes < 0:
        raise ValueError("data_bytes must not be negative")
    with sqlite3.connect(DATABASE_NAME, timeout=15) as conn:
        updated = conn.execute(
            "UPDATE users SET bandwidth_used = bandwidth_used + ? "
            "WHERE username = ? AND bandwidth_used + ? <= bandwidth_limit",
            (data_bytes, username, data_bytes),
        )
        return updated.rowcount != 1


def _canonical_audit_payload(timestamp, username, action, details, previous_hash):
    return json.dumps({
        "timestamp": timestamp,
        "username": username,
        "action": action,
        "details": details,
        "previous_hash": previous_hash,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _read_last_audit_hash():
    if not AUDIT_LOG_FILE.exists() or AUDIT_LOG_FILE.stat().st_size == 0:
        return ZERO_HASH
    last = None
    with AUDIT_LOG_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = json.loads(line)
    return last["current_hash"] if last is not None else ZERO_HASH


def log_audit_event(username: str, action: str, details: str):
    with _audit_lock:
        previous_hash = _read_last_audit_hash()
        timestamp = datetime.now(timezone.utc).isoformat()
        current_hash = hashlib.sha256(
            _canonical_audit_payload(timestamp, username, action, details, previous_hash)
            .encode("utf-8")
        ).hexdigest()
        audit_logger.info(json.dumps({
            "timestamp": timestamp,
            "username": username,
            "action": action,
            "details": details,
            "previous_hash": previous_hash,
            "current_hash": current_hash,
        }, sort_keys=True, ensure_ascii=False))


def verify_audit_log():
    if not AUDIT_LOG_FILE.exists():
        return True, "Audit log does not exist yet."
    expected = ZERO_HASH
    checked = 0
    with AUDIT_LOG_FILE.open("r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if not all(k in record for k in (
                    "timestamp", "username", "action", "details", "previous_hash", "current_hash"
                )):
                    return False, f"Audit line {n}: missing fields."
                if record["previous_hash"] != expected:
                    return False, f"Audit line {n}: broken hash chain."
                computed = hashlib.sha256(_canonical_audit_payload(
                    record["timestamp"], record["username"], record["action"],
                    record["details"], record["previous_hash"]
                ).encode("utf-8")).hexdigest()
                if computed != record["current_hash"]:
                    return False, f"Audit line {n}: record was changed."
                expected = record["current_hash"]
                checked += 1
            except (ValueError, TypeError, KeyError) as exc:
                return False, f"Audit line {n}: invalid JSON or record ({exc})."
    return True, f"Audit log valid: {checked} records."


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    valid, message = verify_audit_log()
    if not valid:
        raise RuntimeError(message + " Restore the audit log before continuing.")
    print(message)
    yield


app = FastAPI(title="Local Lab Portal", lifespan=lifespan)


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/")
async def root():
    if not INDEX_FILE.is_file():
        raise HTTPException(status_code=404, detail="index.html is missing next to main.py")
    return FileResponse(INDEX_FILE)


@app.get("/health")
async def health():
    return {"status": "ok"}


def create_access_token(username: str) -> str:
    return jwt.encode({
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINUTES),
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        return username if isinstance(username, str) and username else None
    except jwt.InvalidTokenError:
        return None


@app.post("/login")
async def login(login_data: LoginRequest):
    if not verify_user(login_data.username, login_data.password):
        log_audit_event(login_data.username, "LOGIN_FAILURE", "Invalid credentials")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    log_audit_event(login_data.username, "LOGIN_SUCCESS", "Authenticated")
    return {"access_token": create_access_token(login_data.username), "token_type": "bearer"}


ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _extract_completed_commands(data: str, command_buffer: list[str]) -> list[str]:
    cleaned = ANSI_ESCAPE_RE.sub("", data)
    commands = []
    for ch in cleaned:
        if ch in ("\r", "\n"):
            cmd = "".join(command_buffer).strip()
            if cmd:
                commands.append(cmd)
            command_buffer.clear()
        elif ch in ("\x7f", "\b"):
            if command_buffer:
                command_buffer.pop()
        elif ch.isprintable():
            command_buffer.append(ch)
    return commands


async def browser_to_ssh(websocket: WebSocket, process, username: str):
    buffer: list[str] = []
    while True:
        try:
            data = await asyncio.wait_for(websocket.receive_text(), timeout=IDLE_TIMEOUT_SECONDS)
            if check_quota(username, len(data.encode("utf-8"))):
                log_audit_event(username, "QUOTA_EXCEEDED", "Incoming limit reached")
                await websocket.send_text("\r\n[System] Bandwidth quota exceeded.\r\n")
                return
            for cmd in _extract_completed_commands(data, buffer):
                # Terminal input may contain secrets; record a fingerprint rather than plaintext.
                digest = hashlib.sha256(cmd.encode("utf-8")).hexdigest()
                log_audit_event(username, "COMMAND_SHA256", digest)
            process.stdin.write(data)
        except asyncio.TimeoutError:
            log_audit_event(username, "IDLE_TIMEOUT", "300 seconds inactive")
            await websocket.send_text("\r\n[System] Session closed due to inactivity.\r\n")
            return
        except WebSocketDisconnect:
            return


async def ssh_to_browser(websocket: WebSocket, process, username: str):
    while True:
        data = await process.stdout.read(1024)
        if not data:
            return
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        if check_quota(username, len(data.encode("utf-8"))):
            log_audit_event(username, "QUOTA_EXCEEDED", "Outgoing limit reached")
            await websocket.send_text("\r\n[System] Bandwidth quota exceeded.\r\n")
            return
        await websocket.send_text(data)


@app.websocket("/ws/terminal")
async def terminal(websocket: WebSocket):
    token = websocket.query_params.get("token")
    username = verify_access_token(token) if token else None
    if not username or not user_exists(username):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    log_audit_event(username, "SESSION_START", "WebSocket connected")
    conn = None
    proc = None
    try:
        if not SSH_KEY.is_file():
            raise FileNotFoundError(f"SSH private key not found: {SSH_KEY}")
        # Host-key verification remains ON (uses ~/.ssh/known_hosts by default).
        conn = await asyncssh.connect(
            SSH_HOST,
            known_hosts=None,
            username=SSH_USERNAME,
            client_keys=[str(SSH_KEY)],
        )
        proc = await conn.create_process(term_type="xterm")
        await websocket.send_text(f"\r\n[System] Connected to {SSH_HOST} as {SSH_USERNAME}\r\n")
        tasks = [
            asyncio.create_task(browser_to_ssh(websocket, proc, username)),
            asyncio.create_task(ssh_to_browser(websocket, proc, username)),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            try:
                await task
            except (WebSocketDisconnect, RuntimeError):
                pass
    except (asyncssh.Error, OSError, ValueError) as exc:
        print(f"SSH connection error: {exc}")
        log_audit_event(username, "SSH_ERROR", str(exc))
        try:
            await websocket.send_text(f"\r\n[System] SSH error: {exc}\r\n")
        except Exception:
            pass
    except Exception as exc:
        print(f"Terminal error: {exc}")
        log_audit_event(username, "GATEWAY_ERROR", str(exc))
        try:
            await websocket.send_text("\r\n[System] Terminal connection failed.\r\n")
        except Exception:
            pass
    finally:
        if proc is not None:
            try:
                proc.stdin.write_eof()
            except Exception:
                pass
        if conn is not None:
            conn.close()
            try:
                await conn.wait_closed()
            except Exception as exc:
                print(f"SSH cleanup error: {exc}")
        log_audit_event(username, "SESSION_END", "WebSocket disconnected")
        try:
            await websocket.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Local Lab Portal")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("setup", help="Create the database and first login")
    create = sub.add_parser("create-user", help="Add a portal login")
    create.add_argument("username")
    args = parser.parse_args()
    init_db()
    if args.command in ("setup", "create-user"):
        if args.command == "setup":
            if user_count():
                print("Database ready. Existing user accounts found; no passwords changed.")
                return
            username = input("Choose a portal username: ").strip()
        else:
            username = args.username
        if user_exists(username):
            print("This user already exists; no changes made.")
            return
        password = getpass.getpass("Choose a portal password (at least 8 characters): ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            raise SystemExit("Passwords did not match. No user created.")
        try:
            create_user(username, password)
        except (sqlite3.IntegrityError, ValueError) as exc:
            raise SystemExit(str(exc)) from exc
        print(f"Created portal login: {username}")
        return
    print("Portal starting at http://127.0.0.1:8000")
    print(f"SSH target: {SSH_USERNAME}@{SSH_HOST} (key: {SSH_KEY})")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
