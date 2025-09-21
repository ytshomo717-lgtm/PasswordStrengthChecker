import tkinter as tk
import re, math

# Function to calculate password entropy
def password_entropy(password):
    charset = 0
    if re.search("[a-z]", password): charset += 26
    if re.search("[A-Z]", password): charset += 26
    if re.search("[0-9]", password): charset += 10
    if re.search("[!@#$%^&*(),.?\":{}|<>]", password): charset += 32
    if charset == 0: 
        return 0
    return round(len(password) * math.log2(charset), 2)

# Function to check strength and show feedback
def check_strength():
    pwd = entry.get()
    entropy = password_entropy(pwd)
    if entropy < 40:
        result.config(text=f"Weak ({entropy} bits)", fg="red")
    elif entropy < 60:
        result.config(text=f"Medium ({entropy} bits)", fg="orange")
    else:
        result.config(text=f"Strong ({entropy} bits)", fg="green")

# GUI setup
root = tk.Tk()
root.title("Password Strength Checker")

tk.Label(root, text="Enter Password:").pack()
entry = tk.Entry(root, show="*"); entry.pack()
tk.Button(root, text="Check Strength", command=check_strength).pack()
result = tk.Label(root, text=""); result.pack()

root.mainloop()
