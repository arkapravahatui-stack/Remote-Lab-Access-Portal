import asyncio
import asyncssh


async def interactive_ssh():
    try:
        async with asyncssh.connect(
            "localhost",
            username="arka",
            client_keys=["/Users/arka/.ssh/id_ed25519"],
            known_hosts=None
        ) as conn:

            process = await conn.create_process(
                term_type="xterm"
            )

            print("Interactive SSH session started.")
            print("Type commands. Type 'exit' to stop.\n")

            while True:
                command = input("SSH> ")

                if command == "exit":
                    break

                process.stdin.write(command + "\n")

                await asyncio.sleep(0.2)

                output = await process.stdout.read(4096)

                print(output)

    except Exception as e:
        print("SSH error:")
        print(e)


asyncio.run(interactive_ssh())