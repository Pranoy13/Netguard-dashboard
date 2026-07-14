import sys, os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from database.db_setup import get_connection


def create_analyst(username, password, role="analyst"):
    conn = get_connection()
    cursor = conn.cursor()
    password_hash = generate_password_hash(password)
    try:
        cursor.execute('''
            INSERT INTO analysts (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
        ''', (username, password_hash, role, datetime.now().isoformat()))
        conn.commit()
        return True, "Account created successfully."
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            return False, "That username is already taken."
        return False, f"Error creating account: {e}"
    finally:
        conn.close()


def verify_analyst(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analysts WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row["password_hash"], password):
        return {"id": row["id"], "username": row["username"], "role": row["role"]}
    return None


if __name__ == '__main__':
    # Run this once to create your first analyst login
    username = input("Enter username: ")
    password = input("Enter password: ")
    create_analyst(username, password, role="admin")