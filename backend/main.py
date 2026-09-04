import asyncio
import asyncssh

from fastapi import FastAPI, WebSocket, WebSocketDisconnect


app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Remote Lab Gateway is running"}


@app.get("/health")
async def health():
    return {"status": "ok"}


async def browser_to_ssh(websocket: WebSocket, process):
    try:
        while True:
            data = await websocket.receive_text()
            process.stdin.write(data)

    except WebSocketDisconnect:
        print("Browser disconnected from WebSocket")

    except Exception as e:
        print("browser_to_ssh error:", e)


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
    await websocket.accept()

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