import bcrypt
import pyotp
import getpass

# Predefined users (username: role)
users = {
    "admin": {"password": bcrypt.hashpw(b"Admin@123", bcrypt.gensalt()), "role": "admin"},
    "student": {"password": bcrypt.hashpw(b"Student@123", bcrypt.gensalt()), "role": "user"}
}

# Generate 2FA secret for demonstration
totp = pyotp.TOTP(pyotp.random_base32())
print("Your 2FA setup code (use Google Authenticator to test):", totp.secret)

# Login function
def login(username):
    if username not in users:
        print("❌ User not found")
        return False

    # Check password
    pwd = getpass.getpass("Enter password: ")
    if bcrypt.checkpw(pwd.encode('utf-8'), users[username]["password"]):
        print("✅ Password verified")

        # Check 2FA
        token = input("Enter 2FA code from Authenticator: ")
        if totp.verify(token):
            print(f"✅ Login successful! Role: {users[username]['role']}")
            return True
        else:
            print("❌ Invalid 2FA token")
            return False
    else:
        print("❌ Invalid password")
        return False

# Example run
if __name__ == "__main__":
    uname = input("Enter username: ")
    login(uname)
