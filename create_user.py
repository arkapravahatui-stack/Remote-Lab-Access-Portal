import sqlite3
from passlib.context import CryptContext

DATABASE_NAME = "users.db"

password_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def create_user(username, password):
    password_hash = password_context.hash(password)

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )

        connection.commit()
        print("User created successfully.")

    except sqlite3.IntegrityError:
        print("Username already exists.")

    finally:
        connection.close()


if __name__ == "__main__":
    username = input("Enter username: ")
    password = input("Enter password: ")

    create_user(username, password)