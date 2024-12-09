import sqlite3
import bcrypt

# Improved - Use bcrypt for securely hashing passwords
def create_user_table():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
    conn.commit()

def hash_password(password):
    """Hash the password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(stored_hash, password):
    """Verify a hashed password"""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

def authenticate(user, passw):
    """Authenticate user by securely checking the password"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Use parameterized query to prevent SQL injection
    cursor.execute("SELECT password FROM users WHERE username = ?", (user,))
    stored_hash = cursor.fetchone()
    
    if stored_hash and verify_password(stored_hash[0], passw):
        return True
    else:
        return False

def get_user_data(user):
    """Retrieve user data securely"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Use parameterized query to prevent SQL injection
    cursor.execute("SELECT * FROM users WHERE username = ?", (user,))
    user_data = cursor.fetchone()
    return user_data

def main():
    """Main function to handle user interaction"""
    create_user_table()  # Ensure the table exists

    # Basic input sanitization (more can be added for further safety)
    user = input("Enter your username: ").strip()
    passw = input("Enter your password: ").strip()

    if not user or not passw:
        print("Username and password cannot be empty!")
        return

    if authenticate(user, passw):
        print("Authenticated successfully!")
        user_data = get_user_data(user)
        print(f"User data: {user_data}")
    else:
        print("Authentication failed!")

if __name__ == "__main__":
    main()
