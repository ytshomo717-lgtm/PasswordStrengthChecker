import tkinter as tk
from tkinter import ttk, messagebox
import bcrypt, pyotp, re, math, datetime

# -------------------------------
# Predefined users with RBAC roles
# -------------------------------
users = {
    "admin": {"password": bcrypt.hashpw(b"Admin@123", bcrypt.gensalt()), "role": "admin"},
    "student": {"password": bcrypt.hashpw(b"Student@123", bcrypt.gensalt()), "role": "user"}
}

# Generate TOTP secret (for 2FA)
totp = pyotp.TOTP(pyotp.random_base32())
print("Use this secret in Google Authenticator (or scan QR if you set that up):", totp.secret)

# -------------------------------
# Utility: Password Entropy
# -------------------------------
def password_entropy(password):
    charset = 0
    if re.search("[a-z]", password): charset += 26
    if re.search("[A-Z]", password): charset += 26
    if re.search("[0-9]", password): charset += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): charset += 32
    if charset == 0: return 0
    return round(len(password) * math.log2(charset), 2)

# -------------------------------
# Logging utility (fixed for Windows)
# -------------------------------
def log_event(event_type, message, user="N/A"):
    safe_message = message.encode("ascii", "ignore").decode()  # remove emojis
    with open("security_log.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] [{event_type}] User: {user} - {safe_message}\n")

# -------------------------------
# Strength Checker Window
# -------------------------------
weak_passwords = ["123456", "password", "qwerty", "letmein", "admin123"]

def open_strength_checker(role):
    win = tk.Toplevel()
    win.title(f"Password Strength Checker - {role}")
    win.geometry("500x400")

    tk.Label(win, text="Enter Password:").pack(pady=10)
    entry = tk.Entry(win, show="*"); entry.pack(pady=5)

    progress = ttk.Progressbar(win, length=300, mode='determinate')
    progress.pack(pady=10)

    result = tk.Label(win, text="", font=("Arial", 12, "bold"))
    result.pack(pady=10)

    def check_strength():
        pwd = entry.get()
        entropy = password_entropy(pwd)
        score = min(100, int(entropy))
        progress["value"] = score

        if entropy < 40:
            result.config(text=f"Weak ({entropy} bits)", fg="red")
            progress.config(style="Red.Horizontal.TProgressbar")
            log_event("Password Check", f"Weak password tested: {pwd}", role)
        elif entropy < 60:
            result.config(text=f"Medium ({entropy} bits)", fg="orange")
            progress.config(style="Orange.Horizontal.TProgressbar")
            log_event("Password Check", f"Medium strength password tested: {pwd}", role)
        elif entropy < 80:
            result.config(text=f"Strong ({entropy} bits)", fg="green")
            progress.config(style="Green.Horizontal.TProgressbar")
            log_event("Password Check", f"Strong password tested: {pwd}", role)
        else:
            result.config(text=f"Very Strong ({entropy} bits)", fg="blue")
            progress.config(style="Blue.Horizontal.TProgressbar")
            log_event("Password Check", f"Very Strong password tested: {pwd}", role)

    tk.Button(win, text="Check Strength", command=check_strength).pack(pady=10)

    # --- Admin-only Features ---
    if role == "admin":
        def dictionary_check():
            pwd = entry.get()
            if pwd in weak_passwords:
                messagebox.showwarning("Dictionary Check", "⚠️ Found in common password list!")
                log_event("Dictionary Check", f"Weak dictionary password used: {pwd}", "admin")
            else:
                messagebox.showinfo("Dictionary Check", "✅ Not in dictionary list.")
                log_event("Dictionary Check", f"Password passed dictionary check: {pwd}", "admin")

        def hashcat_sim():
            pwd = entry.get()
            entropy = password_entropy(pwd)
            if entropy < 40:
                msg = "⚡ Weak password → cracked instantly!"
            elif entropy < 60:
                msg = "⚡ Medium password → cracked in minutes to hours."
            elif entropy < 80:
                msg = "⚡ Strong password → cracked in days to months."
            else:
                msg = "⚡ Very strong password → cracked in years (or practically infeasible)."

            messagebox.showinfo("Hashcat Simulation", msg)
            log_event("Hashcat", f"Hashcat simulation run for [{pwd}] - {msg}", "admin")

        tk.Button(win, text="Dictionary Check", command=dictionary_check).pack(pady=5)
        tk.Button(win, text="Run Hashcat Simulation", command=hashcat_sim).pack(pady=5)

    # Progress bar styles
    style = ttk.Style()
    style.theme_use('default')
    style.configure("Red.Horizontal.TProgressbar", troughcolor='white', background='red')
    style.configure("Orange.Horizontal.TProgressbar", troughcolor='white', background='orange')
    style.configure("Green.Horizontal.TProgressbar", troughcolor='white', background='green')
    style.configure("Blue.Horizontal.TProgressbar", troughcolor='white', background='blue')

# -------------------------------
# Login System with MFA
# -------------------------------
def login():
    username = entry_user.get()
    password = entry_pass.get()
    code = entry_2fa.get()

    if username not in users:
        messagebox.showerror("Error", "❌ User not found")
        log_event("Failed Login", "Unknown username", username)
        return

    if bcrypt.checkpw(password.encode('utf-8'), users[username]["password"]):
        if totp.verify(code):
            role = users[username]["role"]
            messagebox.showinfo("Success", f"✅ Login successful! Role: {role}")
            log_event("Login", "Successful login", username)

            root.withdraw()
            open_strength_checker(role)
        else:
            messagebox.showerror("Error", "❌ Invalid 2FA code")
            log_event("Failed Login", "Invalid 2FA", username)
    else:
        messagebox.showerror("Error", "❌ Invalid password")
        log_event("Failed Login", "Invalid password", username)

# -------------------------------
# GUI Setup
# -------------------------------
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
