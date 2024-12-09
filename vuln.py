import sqlite3
# Hardcoded credentials - bad practice
username = "admin"
password = "password123"
def authenticate(user, passw):
    # Weak authentication - SQL injection vulnerability
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{user}' AND password = '{passw}'"
    cursor.execute(query)
    user_data = cursor.fetchone()
    if user_data:
        return True
    else:
        return False
def get_user_data(user):
    # No input sanitization, vulnerable to SQL injection
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{user}'"
    cursor.execute(query)
    user_data = cursor.fetchone()
    return user_data
def main():
    # Basic user input - no validation or sanitization
    user = input("Enter your username: ")
    passw = input("Enter your password: ")
    if authenticate(user, passw):
        print("Authenticated successfully!")
        user_data = get_user_data(user)
        print(f"User data: {user_data}")
    else:
        print("Authentication failed!")
if __name__ == "__main__":
    main()
