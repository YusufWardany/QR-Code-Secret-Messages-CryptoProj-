# 🔒 Secure QR Messenger (AES-256)

A secure steganography project that encrypts secret messages using **AES-256** and hides them inside **QR Codes**. The system includes a full GUI, user authentication, and protection against brute-force attacks.

## 📋 Project Description
This application allows users to securely transfer sensitive data. Instead of generating a standard QR code (which anyone can scan), this system:
1.  **Encrypts** the message using a password (AES-256).
2.  **Embeds** the encrypted cipher into a QR code.
3.  **Decrypts** the message only if the user provides the correct credentials and password.

It was built using Python and follows Object-Oriented Programming (OOP) principles.

## ✨ Key Features
This project implements 6 advanced security and usability features:

* ✅ **Password Strength Meter:** Real-time validation (Regex) to ensure passwords contain uppercase, lowercase, numbers, and symbols.
* ✅ **Brute-Force Protection:** Locks the user account for 30 seconds after 3 incorrect password attempts.
* ✅ **SHA-256 Key Derivation:** Converts user passwords into secure 32-byte cryptographic keys.
* ✅ **GUI Interface:** A user-friendly, tabbed interface built with `tkinter` (no command line).
* ✅ **File Encryption Support:** Ability to import `.txt` files directly for encryption.
* ✅ **Two-Step Authentication:** Requires both a registered Username and Password to decrypt messages.

## 🛠️ Technologies & Libraries
* **Python 3.x**
* **Tkinter:** For the Graphical User Interface.
* **PyCryptodome:** For AES-CBC encryption and SHA-256 hashing.
* **Qrcode:** To generate the QR code images.
* **Pillow (PIL):** To handle and display images within the GUI.

## ⚙️ Installation & Setup

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/YourUsername/Secure-QR-Messenger.git](https://github.com/YourUsername/Secure-QR-Messenger.git)
    cd Secure-QR-Messenger
    ```

2.  **Install Dependencies**
    You need to install the required Python libraries:
    ```bash
    pip install pycryptodome qrcode[pil] pillow
    ```

3.  **Run the Application**
    ```bash
    python qr_secret_pro.py
    ```

## 🚀 How to Use

### 1. Register
* Go to the **Register User** tab.
* Create a username and a strong password (watch the strength meter turn green).

### 2. Encrypt (Send)
* Go to the **Encrypt** tab.
* Type a message OR click **"Import .txt File"** to load a document.
* Enter a password to lock the message.
* Click **Generate QR** and save the image.

### 3. Decrypt (Receive)
* Scan the QR code (or copy the text string).
* Go to the **Decrypt** tab.
* Paste the encrypted string.
* Enter your **Username** and **Password** (Two-Step Auth).
* Click **Decrypt** to reveal the secret.

## 📂 Project Structure
```text
Secure-QR-Messenger/
│
├── qr_secret_pro.py   # Main source code (Logic + GUI)
├── README.md          # Project documentation
└── requirements.txt   # List of dependencies
