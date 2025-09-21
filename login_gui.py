import tkinter as tk
from tkinter import messagebox
import bcrypt
import pyotp

# --- Predefined users with hashed passwords ---
users = {
    "admin": {"password": bcrypt.hashpw(b"Admin@123", bcrypt.gensalt()), "role": "admin"},
    "student": {"password": bcrypt.hashpw(b"Student@123", bcrypt.gensalt()), "role": "user"}
}

# --- Generate TOTP secret for demo ---
totp = pyotp.TOTP(pyotp.random_base32())
print("🔑 Use this secret in Google Authenticator (or scan QR if you set that up):", totp.secret)

# --- Login Function ---
def login():
    username = entry_user.get()
    password = entry_pass.get()

    if username not in users:
        messagebox.showerror("Error", "❌ User not found")
        return

    if bcrypt.checkpw(password.encode('utf-8'), users[username]["password"]):
        # Ask for 2FA code
        code = entry_2fa.get()
        if totp.verify(code):
            role = users[username]["role"]
            messagebox.showinfo("Success", f"✅ Login successful! Role: {role}")
        else:
            messagebox.showerror("Error", "❌ Invalid 2FA code")
    else:
        messagebox.showerror("Error", "❌ Invalid password")

# --- GUI Setup ---
root = tk.Tk()
root.title("Secure Login with MFA")

tk.Label(root, text="Username:").pack()
entry_user = tk.Entry(root); entry_user.pack()

tk.Label(root, text="Password:").pack()
entry_pass = tk.Entry(root, show="*"); entry_pass.pack()

tk.Label(root, text="2FA Code:").pack()
entry_2fa = tk.Entry(root); entry_2fa.pack()

tk.Button(root, text="Login", command=login).pack(pady=10)

root.mainloop()
