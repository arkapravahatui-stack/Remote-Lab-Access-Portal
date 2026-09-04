import asyncio
import asyncssh


async def test_ssh():
    try:
        async with asyncssh.connect(
            "localhost",
            username="arka",
            client_keys=["/Users/arka/.ssh/id_ed25519"],
            known_hosts=None
        ) as conn:

            result = await conn.run("whoami")

            print("SSH connection successful!")
            print("Remote user:", result.stdout.strip())

    except Exception as e:
        print("SSH connection failed:")
        print(e)


asyncio.run(test_ssh())