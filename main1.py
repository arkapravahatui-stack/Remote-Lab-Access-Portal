import asyncio
import sqlite3
import hashlib
from datetime import datetime, timedelta, timezone

import asyncssh
import jwt

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext


def check_quota(username: str, data_bytes: int) -> bool:
    db_path = r'C:\Users\hp\OneDrive\Desktop\lab-portal\users.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT bandwidth_used, bandwidth_limit FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return False
        
    used, limit = row
    new_total = used + data_bytes
    
    if new_total > limit:
        conn.close()
        return True 
        
    cursor.execute("UPDATE users SET bandwidth_used = ? WHERE username = ?", (new_total, username))
    conn.commit()
    conn.close()
    
    return False


def log_audit_event(username: str, action: str, details: str):
    db_path = r'C:\Users\hp\OneDrive\Desktop\lab-portal\users.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            action TEXT,
            details TEXT,
            previous_hash TEXT,
            current_hash TEXT
        )
    """)
    
    cursor.execute("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    prev_hash = row[0] if row else "0000000000000000000000000000000000000000000000000000000000000000"
    
    timestamp = datetime.now(timezone.utc).isoformat()
    raw_data = f"{timestamp}{username}{action}{details}{prev_hash}"
    current_hash = hashlib.sha256(raw_data.encode('utf-8')).hexdigest()
    
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, username, action, details, previous_hash, current_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (timestamp, username, action, details, prev_hash, current_hash))
    
    conn.commit()
    conn.close()


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_NAME = "users.db"
JWT_SECRET = "change-this-secret-later"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 30
IDLE_TIMEOUT_SECONDS = 300 

password_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/")
async def root():
    return FileResponse(r"C:\Users\hp\OneDrive\Desktop\lab-portal\index.html")


@app.get("/health")
async def health():
    return {"status": "ok"}


def verify_user(username, password):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,)
    )

    result = cursor.fetchone()
    connection.close()

    if result is None:
        return False

    password_hash = result[0]
    return password_context.verify(password, password_hash)


def create_access_token(username):
    expiry = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINUTES)
    payload = {
        "sub": username,
        "exp": expiry
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_access_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        
        if username is None:
            return None
            
        return username

    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@app.post("/login")
async def login(login_data: LoginRequest):
    valid_user = verify_user(login_data.username, login_data.password)

    if not valid_user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token(login_data.username)

    return {
        "access_token": token,
        "token_type": "bearer"
    }


async def browser_to_ssh(websocket: WebSocket, process, username: str):
    while True:
        try:
            data = await asyncio.wait_for(
                websocket.receive_text(),
                timeout=IDLE_TIMEOUT_SECONDS
            )

            data_size = len(data.encode('utf-8'))
            if check_quota(username, data_size):
                await websocket.send_text("\r\n[System] Bandwidth quota exceeded. Terminating session.\r\n")
                break

            process.stdin.write(data)

        except asyncio.TimeoutError:
            await websocket.send_text("\r\nSession closed due to inactivity.\r\n")
            print("Session closed due to idle timeout")
            break

        except WebSocketDisconnect:
            print("Browser disconnected from WebSocket")
            break

        except Exception as e:
            print("browser_to_ssh error:", e)
            break


async def ssh_to_browser(websocket: WebSocket, process, username: str):
    try:
        while True:
            data = await process.stdout.read(1024)

            if not data:
                break

            data_size = len(data.encode('utf-8') if isinstance(data, str) else data)
            if check_quota(username, data_size):
                await websocket.send_text("\r\n[System] Bandwidth quota exceeded. Terminating session.\r\n")
                break

            await websocket.send_text(data)

    except WebSocketDisconnect:
        print("WebSocket closed while sending SSH output")

    except Exception as e:
        print("ssh_to_browser error:", e)


@app.websocket("/ws/terminal")
async def terminal(websocket: WebSocket):
    token = websocket.query_params.get("token")

    if token is None:
        await websocket.close(code=1008)
        print("WebSocket rejected: no token")
        return

    username = verify_access_token(token)

    if username is None:
        await websocket.close(code=1008)
        print("WebSocket rejected: invalid or expired token")
        return

    await websocket.accept()
    print(f"Authenticated WebSocket user: {username}")
    log_audit_event(username, "SESSION_START", f"User {username} connected via WebSocket.")

    ssh_connection = None
    ssh_process = None

    try:
        ssh_connection = await asyncssh.connect(
            "localhost",
            username="hp",
            client_keys=["C:/Users/hp/.ssh/id_ed25519"],
            known_hosts=None
        )

        ssh_process = await ssh_connection.create_process(term_type="xterm")

        await websocket.send_text(f"\r\nAuthenticated as {username}\r\n")
        await websocket.send_text("\r\nConnected to SSH machine.\r\n")

        browser_task = asyncio.create_task(
            browser_to_ssh(websocket, ssh_process, username)
        )

        ssh_task = asyncio.create_task(
            ssh_to_browser(websocket, ssh_process, username)
        )

        done, pending = await asyncio.wait(
            [browser_task, ssh_task],
            return_when=asyncio.FIRST_COMPLETED
        )

        for task in pending:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)

        for task in done:
            try:
                await task
            except Exception as e:
                print("Task finished with error:", e)

    except WebSocketDisconnect:
        print("Browser disconnected")

    except asyncssh.Error as e:
        print("SSH error:", e)
        try:
            await websocket.send_text("\r\nSSH connection error.\r\n")
        except Exception:
            pass

    except Exception as e:
        print("Gateway error:", e)
        try:
            await websocket.send_text("\r\nGateway error.\r\n")
        except Exception:
            pass

    finally:
        if ssh_process:
            try:
                ssh_process.stdin.write_eof()
            except Exception:
                pass

        if ssh_connection:
            ssh_connection.close()
            try:
                await ssh_connection.wait_closed()
            except Exception:
                pass

        log_audit_event(username, "SESSION_END", f"User {username} session terminated.")
        print("SSH session cleaned up")