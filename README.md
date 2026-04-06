# 🔐 ENP TOOL KIT (Encryption & Decryption GUI)

A powerful **Python-based GUI application** for secure **encryption and decryption of text and files** using multiple cryptographic algorithms.

Built with **Tkinter** and modern cryptographic standards, this tool provides an easy-to-use interface for performing encryption operations without command-line complexity.

---

## 🚀 Features

* 🖥️ User-friendly GUI (Tkinter-based)
* 🔐 Multiple encryption algorithms:

  * AES-128 / AES-192 / AES-256
  * ChaCha20
  * TripleDES
  * Fernet
  * RSA Hybrid Encryption
* 📂 Supports both:

  * Text encryption/decryption
  * File encryption/decryption
* 🔑 Password-based encryption (PBKDF2 with SHA-256)
* 🔐 Secure key generation:

  * Fernet key
  * RSA public/private key pair
* 📁 Automatic output file generation

---

## 🛠️ Tech Stack

* Python 3.x
* Tkinter (GUI)
* Cryptography Library

---

## ⚙️ Installation

1. Clone the repository:

```bash
git clone https://github.com/your-username/enp-toolkit.git
```

2. Navigate into the project folder:

```bash
cd enp-toolkit
```

3. Install dependencies:

```bash
pip install cryptography
```

---

## ▶️ Usage

Run the application:

```bash
python main.py
```

After running:

* A GUI window will open
* Select encryption method
* Choose mode (Text / File)
* Enter password 
* Click **Encrypt** or **Decrypt**

---

<img width="942" height="734" alt="Screenshot 2026-04-06 121216" src="https://github.com/user-attachments/assets/1a9a39eb-21f4-4e4c-b02b-2f032c9fa944" />


---

## 🔑 Encryption Methods Explained

| Method     | Type                   | Description                            |
| ---------- | ---------------------- | -------------------------------------- |
| AES        | Symmetric              | Strong industry-standard encryption    |
| ChaCha20   | Stream Cipher          | Fast and secure alternative to AES     |
| TripleDES  | Symmetric (Legacy)     | Older encryption (not recommended)     |
| Fernet     | Symmetric (High-level) | Simple secure encryption with key file |
| RSA Hybrid | Asymmetric + Symmetric | Uses RSA + AES for high security       |

---

## 📌 Key Features in Detail

* **PBKDF2 Key Derivation**
  Converts passwords into secure cryptographic keys

* **RSA Hybrid Encryption**
  Encrypts data using AES and secures AES key using RSA

* **Secure File Handling**

  * Encrypted files are saved with extensions like `.aes`, `.chacha`, `.tdes`, `.rhy`
  * Decrypted files are saved with `.dec` extension

---

## ⚠️ Disclaimer

This project is created for **educational and ethical use only**.
Do not use this tool for illegal activities or unauthorized data access.

---

## 🚀 Future Improvements

* Add drag & drop file support
* Improve UI design
* Add password strength checker
* Add logging system
* Support more encryption algorithms

---

## 👨‍💻 Author

**Ketan Saini**

---

## ⭐ Support

If you found this project helpful, consider giving it a ⭐ on GitHub!
