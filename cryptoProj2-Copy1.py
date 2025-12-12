#!/usr/bin/env python
# coding: utf-8

# In[2]:


import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import qrcode
import hashlib
import base64
import time
import re
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# =============================================================================
#  BACKEND LOGIC: AUTHENTICATION & SECURITY
# =============================================================================

class AuthManager:
    """
    Handles User Management, Authentication, and Brute-Force Protection.
    """
    def __init__(self):
        # [FEATURE 6] Two-Step Authentication: We need a database of users.
        # In a real app, use SQLite. Here, we use a dictionary.
        self.users_db = {} 
        
        # [FEATURE 2] Brute-Force Protection
        self.failed_attempts = {}     # Format: {username: int_count}
        self.lockout_until = {}       # Format: {username: timestamp}
        self.MAX_ATTEMPTS = 3         # Lock after 3 wrongs
        self.LOCKOUT_DURATION = 30    # Lock for 30 seconds

    def check_password_strength(self, password):
        """
        [FEATURE 1] Password Strength Check
        Returns: (bool_is_strong, str_feedback_message)
        """
        if len(password) < 8:
            return False, "Too Short (Min 8 chars)"
        if not re.search(r"[A-Z]", password):
            return False, "Missing Uppercase (A-Z)"
        if not re.search(r"[a-z]", password):
            return False, "Missing Lowercase (a-z)"
        if not re.search(r"[0-9]", password):
            return False, "Missing Digit (0-9)"
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Missing Special Char (!@#...)"
        
        return True, "Strong Password ✅"

    def register(self, username, password):
        if username in self.users_db:
            return False, "Username already taken."
        
        is_strong, msg = self.check_password_strength(password)
        if not is_strong:
            return False, f"Weak Password: {msg}"
            
        self.users_db[username] = password
        return True, "Registration Successful!"

    def login(self, username, password):
        """
        [FEATURE 2] & [FEATURE 6]: Verifies user + password and checks brute-force limits.
        """
        current_time = time.time()

        # 1. Check if user is currently locked out
        if username in self.lockout_until:
            if current_time < self.lockout_until[username]:
                remaining = int(self.lockout_until[username] - current_time)
                return False, f"Account Locked! Try again in {remaining}s"
            else:
                # Lockout expired, reset
                del self.lockout_until[username]
                self.failed_attempts[username] = 0

        # 2. Check User Existence
        if username not in self.users_db:
            return False, "User not registered."

        # 3. Verify Password
        if self.users_db[username] == password:
            self.failed_attempts[username] = 0 # Reset on success
            return True, "Login Success"
        else:
            # Increment failure counter
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
            attempts = self.failed_attempts[username]
            
            if attempts >= self.MAX_ATTEMPTS:
                self.lockout_until[username] = current_time + self.LOCKOUT_DURATION
                return False, f"Max attempts reached. Locked for {self.LOCKOUT_DURATION}s."
            
            return False, f"Wrong Password! ({self.MAX_ATTEMPTS - attempts} attempts left)"


class CryptoManager:
    """
    Handles AES Encryption and SHA-256 Key Derivation.
    """
    def get_aes_key(self, password):
        """
        [FEATURE 3] SHA-256 Key Derivation
        Converts any password string into a valid 32-byte AES key.
        """
        hasher = hashlib.sha256()
        hasher.update(password.encode('utf-8'))
        return hasher.digest()

    def encrypt(self, plain_text, password):
        try:
            key = self.get_aes_key(password)
            iv = get_random_bytes(16) # Initialization Vector
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
            
            # Return as Base64 string (IV + Ciphertext)
            return base64.b64encode(iv + encrypted_bytes).decode('utf-8')
        except Exception as e:
            print(f"Encryption Error: {e}")
            return None

    def decrypt(self, encrypted_b64, password):
        try:
            raw_data = base64.b64decode(encrypted_b64)
            iv = raw_data[:16]
            ciphertext = raw_data[16:]
            
            key = self.get_aes_key(password)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted_bytes.decode('utf-8')
        except (ValueError, KeyError):
            return None # Decryption failed (usually wrong key/password)


# =============================================================================
#  FRONTEND: GUI INTERFACE (Tkinter)
# =============================================================================

class SecureQRApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ QR Secret Manager - Pro Version")
        self.root.geometry("650x750")
        self.auth = AuthManager()
        self.crypto = CryptoManager()

        # Apply a clean style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", font=("Helvetica", 10, "bold"), padding=6)
        style.configure("TLabel", font=("Helvetica", 10))

        # [FEATURE 4] GUI Interface Structure (Notebook/Tabs)
        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill='both', expand=True, padx=10, pady=10)

        # Create Tab Frames
        self.tab_reg = ttk.Frame(self.tabs)
        self.tab_enc = ttk.Frame(self.tabs)
        self.tab_dec = ttk.Frame(self.tabs)

        self.tabs.add(self.tab_reg, text=" 1. Register User ")
        self.tabs.add(self.tab_enc, text=" 2. Encrypt & Generate ")
        self.tabs.add(self.tab_dec, text=" 3. Decrypt Message ")

        # Initialize UI Components
        self.init_register_ui()
        self.init_encrypt_ui()
        self.init_decrypt_ui()

    # -------------------------------------------------------------------------
    # TAB 1: REGISTRATION UI
    # -------------------------------------------------------------------------
    def init_register_ui(self):
        frame = self.tab_reg
        ttk.Label(frame, text="Create a New Account", font=("Helvetica", 16, "bold")).pack(pady=20)

        # Username
        ttk.Label(frame, text="Choose Username:").pack(anchor="w", padx=100)
        self.reg_user_entry = ttk.Entry(frame, width=40)
        self.reg_user_entry.pack(pady=5)

        # Password
        ttk.Label(frame, text="Choose Password:", font=("Helvetica", 10)).pack(anchor="w", padx=100)
        self.reg_pass_entry = ttk.Entry(frame, show="*", width=40)
        self.reg_pass_entry.pack(pady=5)
        
        # Real-time Strength Indicator (Label)
        self.strength_lbl = ttk.Label(frame, text="Password Strength: Enter Password", foreground="gray")
        self.strength_lbl.pack(pady=5)
        
        # Bind key release to check strength dynamically
        self.reg_pass_entry.bind("<KeyRelease>", self.update_strength_meter)

        btn = ttk.Button(frame, text="Register User", command=self.handle_registration)
        btn.pack(pady=20)

    def update_strength_meter(self, event):
        pwd = self.reg_pass_entry.get()
        if not pwd:
            self.strength_lbl.config(text="Password Strength: Enter Password", foreground="gray")
            return
            
        is_strong, msg = self.auth.check_password_strength(pwd)
        if is_strong:
            self.strength_lbl.config(text=f"Strength: {msg}", foreground="green")
        else:
            self.strength_lbl.config(text=f"Strength: {msg}", foreground="red")

    def handle_registration(self):
        user = self.reg_user_entry.get()
        pwd = self.reg_pass_entry.get()
        
        if not user or not pwd:
            messagebox.showwarning("Input Error", "All fields are required.")
            return

        success, msg = self.auth.register(user, pwd)
        if success:
            messagebox.showinfo("Success", msg)
            self.reg_user_entry.delete(0, tk.END)
            self.reg_pass_entry.delete(0, tk.END)
            self.strength_lbl.config(text="")
        else:
            messagebox.showerror("Registration Failed", msg)

    # -------------------------------------------------------------------------
    # TAB 2: ENCRYPTION UI (Feature 5: File Support)
    # -------------------------------------------------------------------------
    def init_encrypt_ui(self):
        frame = self.tab_enc
        ttk.Label(frame, text="Encryption Station", font=("Helvetica", 16, "bold")).pack(pady=15)

        # Message Input Area
        lbl_frame = ttk.LabelFrame(frame, text="Input Method")
        lbl_frame.pack(fill="x", padx=20, pady=5)
        
        ttk.Label(lbl_frame, text="Type Message OR Load Text File:").pack(pady=5)
        
        # [FEATURE 5] Text File Encryption Support
        ttk.Button(lbl_frame, text="📂 Import .txt File", command=self.load_text_file).pack(pady=5)
        
        self.txt_input = tk.Text(lbl_frame, height=5, width=50)
        self.txt_input.pack(pady=10, padx=10)

        # Password for Encryption
        pass_frame = ttk.Frame(frame)
        pass_frame.pack(pady=10)
        ttk.Label(pass_frame, text="Secret Password for this Message:").pack()
        self.enc_pass_entry = ttk.Entry(pass_frame, show="*", width=30)
        self.enc_pass_entry.pack(pady=5)

        # Generate Button
        ttk.Button(frame, text="🔒 Encrypt & Create QR", command=self.handle_encryption).pack(pady=10)

        # QR Display
        self.qr_label = ttk.Label(frame)
        self.qr_label.pack(pady=10)
        
        # Cipher text display (for copy-paste testing)
        ttk.Label(frame, text="Encrypted Cipher String (Copy this if you can't scan):").pack()
        self.cipher_entry = ttk.Entry(frame, width=60)
        self.cipher_entry.pack(pady=5)

    def load_text_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.txt_input.delete("1.0", tk.END)
                    self.txt_input.insert(tk.END, content)
                messagebox.showinfo("File Loaded", "File content imported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file: {e}")

    def handle_encryption(self):
        msg = self.txt_input.get("1.0", tk.END).strip()
        pwd = self.enc_pass_entry.get()

        if not msg:
            messagebox.showwarning("Missing Data", "Please enter a message or load a file.")
            return
        
        # [FEATURE 1] Re-check strength here for safety
        is_strong, reason = self.auth.check_password_strength(pwd)
        if not is_strong:
            proceed = messagebox.askyesno("Weak Password Warning", f"Your password is weak: {reason}.\n\nDo you want to proceed anyway?")
            if not proceed:
                return

        # Perform Encryption
        encrypted_str = self.crypto.encrypt(msg, pwd)
        
        if encrypted_str:
            # Show Cipher Text
            self.cipher_entry.delete(0, tk.END)
            self.cipher_entry.insert(0, encrypted_str)
            
            # Create QR Code
            qr = qrcode.make(encrypted_str)
            
            # Save QR
            save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
            if save_path:
                qr.save(save_path)
                
                # Display in GUI
                img = Image.open(save_path)
                img = img.resize((200, 200)) # Resize for GUI
                self.photo_img = ImageTk.PhotoImage(img) # Keep reference
                self.qr_label.config(image=self.photo_img)
                
                messagebox.showinfo("Success", "QR Code Saved and Encrypted successfully!")
            else:
                messagebox.showinfo("Cancelled", "QR Code generation cancelled.")
        else:
            messagebox.showerror("Error", "Encryption process failed.")

    # -------------------------------------------------------------------------
    # TAB 3: DECRYPTION UI (Feature 2 & 6: Auth + Brute Force)
    # -------------------------------------------------------------------------
    def init_decrypt_ui(self):
        frame = self.tab_dec
        ttk.Label(frame, text="Secure Decryption", font=("Helvetica", 16, "bold")).pack(pady=15)

        # Encrypted String Input
        ttk.Label(frame, text="1. Paste Encrypted String (from QR scan):").pack(anchor="w", padx=50)
        self.dec_cipher_entry = ttk.Entry(frame, width=60)
        self.dec_cipher_entry.pack(pady=5)

        separator = ttk.Separator(frame, orient='horizontal')
        separator.pack(fill='x', padx=50, pady=15)

        # [FEATURE 6] Two-Step Authentication Section
        auth_frame = ttk.LabelFrame(frame, text="2. Authenticate to Unlock (Two-Step Auth)")
        auth_frame.pack(pady=5, padx=20, fill="x")

        ttk.Label(auth_frame, text="Registered Username:").pack()
        self.dec_user_entry = ttk.Entry(auth_frame, width=30)
        self.dec_user_entry.pack(pady=2)

        ttk.Label(auth_frame, text="User Password:").pack()
        self.dec_pass_entry = ttk.Entry(auth_frame, show="*", width=30)
        self.dec_pass_entry.pack(pady=2)

        # Button
        ttk.Button(frame, text="🔓 Authenticate & Decrypt", command=self.handle_decryption).pack(pady=20)

        # Result Area
        ttk.Label(frame, text="Decrypted Message:").pack(anchor="w", padx=50)
        self.res_text = tk.Text(frame, height=5, width=60, state="disabled", bg="#f0f0f0")
        self.res_text.pack(pady=5)

    def handle_decryption(self):
        cipher_text = self.dec_cipher_entry.get()
        user = self.dec_user_entry.get()
        pwd = self.dec_pass_entry.get()

        if not cipher_text or not user or not pwd:
            messagebox.showwarning("Missing Data", "Please fill in all fields (Cipher, User, Password).")
            return

        # 1. AUTHENTICATE [FEATURE 6] & CHECK BRUTE FORCE [FEATURE 2]
        success, auth_msg = self.auth.login(user, pwd)
        
        if not success:
            messagebox.showerror("Authentication Failed", auth_msg)
            return

        # 2. DECRYPT [FEATURE 3 - AES with SHA256 key]
        # Note: We use the user's password as the key for this demo.
        decrypted_msg = self.crypto.decrypt(cipher_text, pwd)

        self.res_text.config(state="normal")
        self.res_text.delete("1.0", tk.END)
        
        if decrypted_msg:
            self.res_text.config(bg="#e6fffa") # Light green background for success
            self.res_text.insert(tk.END, decrypted_msg)
            messagebox.showinfo("Success", "Message Decrypted Successfully!")
        else:
            self.res_text.config(bg="#ffe6e6") # Light red background for failure
            self.res_text.insert(tk.END, "⚠️ DECRYPTION FAILED.\nAuthentication was correct, but the message content could not be decrypted.\nDid you use the correct password for this specific message?")
        
        self.res_text.config(state="disabled")

# =============================================================================
#  MAIN ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureQRApp(root)
    root.mainloop()


# In[ ]:




