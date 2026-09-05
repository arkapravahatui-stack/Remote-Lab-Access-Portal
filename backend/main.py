import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone

import asyncssh
import jwt

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext


app = FastAPI()


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
    return {"message": "Remote Lab Gateway is running"}


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

    return password_context.verify(
        password,
        password_hash
    )


def create_access_token(username):
    expiry = datetime.now(timezone.utc) + timedelta(
        minutes=JWT_EXPIRY_MINUTES
    )

    payload = {
        "sub": username,
        "exp": expiry
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )


def verify_access_token(token):
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )

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

    valid_user = verify_user(
        login_data.username,
        login_data.password
    )

    if not valid_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    token = create_access_token(
        login_data.username
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }


async def browser_to_ssh(websocket: WebSocket, process):
    while True:
        try:
            data = await asyncio.wait_for(
                websocket.receive_text(),
                timeout=IDLE_TIMEOUT_SECONDS
            )

            process.stdin.write(data)

        except asyncio.TimeoutError:
            await websocket.send_text(
                "\r\nSession closed due to inactivity.\r\n"
            )

            print("Session closed due to idle timeout")
            break

        except WebSocketDisconnect:
            print("Browser disconnected from WebSocket")
            break

        except Exception as e:
            print("browser_to_ssh error:", e)
            break


async def ssh_to_browser(websocket: WebSocket, process):
    try:
        while True:
            data = await process.stdout.read(1024)

            if not data:
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

    ssh_connection = None
    ssh_process = None

    try:
        ssh_connection = await asyncssh.connect(
            "localhost",
            username="arka",
            client_keys=["/Users/arka/.ssh/id_ed25519"],
            known_hosts=None
        )

        ssh_process = await ssh_connection.create_process(
            term_type="xterm"
        )

        await websocket.send_text(
            f"\r\nAuthenticated as {username}\r\n"
        )

        await websocket.send_text(
            "\r\nConnected to SSH machine.\r\n"
        )

        browser_task = asyncio.create_task(
            browser_to_ssh(websocket, ssh_process)
        )

        ssh_task = asyncio.create_task(
            ssh_to_browser(websocket, ssh_process)
        )

        done, pending = await asyncio.wait(
            [browser_task, ssh_task],
            return_when=asyncio.FIRST_COMPLETED
        )

        for task in pending:
            task.cancel()

        await asyncio.gather(
            *pending,
            return_exceptions=True
        )

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
            await websocket.send_text(
                "\r\nSSH connection error.\r\n"
            )
        except Exception:
            pass

    except Exception as e:
        print("Gateway error:", e)

        try:
            await websocket.send_text(
                "\r\nGateway error.\r\n"
            )
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

        print("SSH session cleaned up")