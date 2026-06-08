import sqlite3
import hashlib
import re
from datetime import datetime

# =========================================================
# DATABASE CONNECTION
# =========================================================

conn = sqlite3.connect("secure_system.db")
cursor = conn.cursor()

# =========================================================
# CREATE USERS TABLE
# =========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT
)
""")

conn.commit()

# =========================================================
# PASSWORD HASHING FUNCTION
# SECURITY:
# - Prevents plaintext password storage
# =========================================================

def hash_password(password):

    return hashlib.sha256(password.encode()).hexdigest()

# =========================================================
# PASSWORD VALIDATION
# SECURITY:
# - Enforces strong password policy
# =========================================================

def validate_password(password):

    if len(password) < 8:
        return False, "Password must contain at least 8 characters"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"

    return True, "Strong Password"

# =========================================================
# USER REGISTRATION
# SECURITY FEATURES:
# - Input validation
# - Password hashing
# - Duplicate username prevention
# =========================================================

def register_user():

    print("""
=================================================
                USER REGISTRATION
=================================================

PASSWORD REQUIREMENTS:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
""")

    username = input("Enter Username : ").strip()
    password = input("Enter Password : ").strip()

    # Input Validation
    if not username or not password:
        print("\n[!] Username and Password cannot be empty")
        return

    # Password Validation
    valid, message = validate_password(password)

    if not valid:
        print(f"\n[!] {message}")
        return

    # Hash Password
    hashed_password = hash_password(password)

    try:

        # Secure Parameterized Query
        cursor.execute(
            """
            INSERT INTO users (username, password, created_at)
            VALUES (?, ?, ?)
            """,
            (
                username,
                hashed_password,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        )

        conn.commit()

        print("\n[+] User Registered Successfully")

    except sqlite3.IntegrityError:

        print("\n[!] Username already exists")

# =========================================================
# USER LOGIN
# SECURITY FEATURES:
# - Secure authentication
# - SQL Injection prevention
# - Password hashing verification
# =========================================================

def login_user():

    print("""
=================================================
                    USER LOGIN
=================================================
""")

    username = input("Enter Username : ").strip()
    password = input("Enter Password : ").strip()

    if not username or not password:
        print("\n[!] Username and Password cannot be empty")
        return

    # Hash Input Password
    hashed_password = hash_password(password)

    # Secure Query
    query = """
    SELECT * FROM users
    WHERE username=? AND password=?
    """

    cursor.execute(query, (username, hashed_password))

    result = cursor.fetchone()

    if result:

        print("\n[+] Login Successful")
        print(f"Welcome, {username}")

    else:

        print("\n[!] Invalid Username or Password")

# =========================================================
# DISPLAY REGISTERED USERS
# =========================================================

def show_users():

    print("""
=================================================
                REGISTERED USERS
=================================================
""")

    cursor.execute(
        """
        SELECT id, username, created_at
        FROM users
        """
    )

    users = cursor.fetchall()

    if not users:

        print("No users found")
        return

    for user in users:

        print(f"""
ID         : {user[0]}
Username   : {user[1]}
Created At : {user[2]}
""")

# =========================================================
# SECURITY AUDIT REPORT
# =========================================================

def security_report():

    print("""
=================================================
              SECURITY REVIEW REPORT
=================================================

VULNERABILITIES REVIEWED:
-------------------------
1. SQL Injection
2. Weak Passwords
3. Plaintext Password Storage
4. Unsafe Input Handling

SECURITY IMPROVEMENTS IMPLEMENTED:
----------------------------------
[+] Parameterized SQL Queries
[+] Password Hashing using SHA-256
[+] Strong Password Validation
[+] Input Validation
[+] Duplicate Username Protection

SECURE CODING PRACTICES USED:
-----------------------------
- Secure Authentication
- Database Security
- Input Sanitization
- Strong Password Enforcement

STATUS:
-------
APPLICATION REVIEW COMPLETED SUCCESSFULLY
""")

# =========================================================
# MAIN MENU
# =========================================================

while True:

    print("""
=================================================
         SECURE LOGIN MANAGEMENT SYSTEM
=================================================

1. Register User
2. Login User
3. Show Registered Users
4. Security Review Report
5. Exit
""")

    choice = input("Enter Choice : ")

    if choice == "1":

        register_user()

    elif choice == "2":

        login_user()

    elif choice == "3":

        show_users()

    elif choice == "4":

        security_report()

    elif choice == "5":

        print("\nExiting Secure System...")
        break

    else:

        print("\n[!] Invalid Choice")

# =========================================================
# CLOSE DATABASE CONNECTION
# =========================================================

conn.close()
