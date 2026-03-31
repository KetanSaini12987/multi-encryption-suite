import os
import json
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


APP_TITLE = "ENP TOOL KIT By KETAN"
WINDOW_SIZE = "760x560"

FERNET_KEY_FILE = "fernet.key"
RSA_PRIVATE_FILE = "rsa_private.pem"
RSA_PUBLIC_FILE = "rsa_public.pem"

METHODS = [
    "AES-128",
    "AES-192",
    "AES-256",
    "Fernet",
    "ChaCha20",
    "TripleDES",
    "RSA-Hybrid"
]


def derive_key(password: str, salt: bytes, length: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=200000,
    )
    return kdf.derive(password.encode("utf-8"))


def default_output_path(input_path: str, suffix: str) -> str:
    folder = os.path.dirname(input_path)
    base = os.path.basename(input_path)
    return os.path.join(folder, base + suffix)


def save_bytes(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def load_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ---------- Fernet ----------
def generate_fernet_key():
    key = Fernet.generate_key()
    save_bytes(FERNET_KEY_FILE, key)


def load_fernet_key():
    if not os.path.exists(FERNET_KEY_FILE):
        return None
    return load_bytes(FERNET_KEY_FILE)


# ---------- RSA ----------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(RSA_PRIVATE_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(RSA_PUBLIC_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def load_rsa_public_key():
    if not os.path.exists(RSA_PUBLIC_FILE):
        return None
    with open(RSA_PUBLIC_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_rsa_private_key():
    if not os.path.exists(RSA_PRIVATE_FILE):
        return None
    with open(RSA_PRIVATE_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ---------- AES CBC ----------
def aes_encrypt(data: bytes, password: str, bits: int) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt, bits // 8)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    package = {
        "type": f"AES-{bits}",
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(package).encode("utf-8")


def aes_decrypt(package_bytes: bytes, password: str) -> bytes:
    package = json.loads(package_bytes.decode("utf-8"))
    salt = base64.b64decode(package["salt"])
    iv = base64.b64decode(package["iv"])
    ciphertext = base64.b64decode(package["data"])
    bits = int(package["type"].split("-")[1])

    key = derive_key(password, salt, bits // 8)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------- ChaCha20 ----------
def chacha20_encrypt(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(16)
    key = derive_key(password, salt, 32)

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    enc = cipher.encryptor()
    ciphertext = enc.update(data)

    package = {
        "type": "ChaCha20",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(package).encode("utf-8")


def chacha20_decrypt(package_bytes: bytes, password: str) -> bytes:
    package = json.loads(package_bytes.decode("utf-8"))
    salt = base64.b64decode(package["salt"])
    nonce = base64.b64decode(package["nonce"])
    ciphertext = base64.b64decode(package["data"])

    key = derive_key(password, salt, 32)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    dec = cipher.decryptor()
    return dec.update(ciphertext)


# ---------- TripleDES ----------
def tdes_encrypt(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(8)
    key = derive_key(password, salt, 24)

    padder = sym_padding.PKCS7(64).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    package = {
        "type": "TripleDES",
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(package).encode("utf-8")


def tdes_decrypt(package_bytes: bytes, password: str) -> bytes:
    package = json.loads(package_bytes.decode("utf-8"))
    salt = base64.b64decode(package["salt"])
    iv = base64.b64decode(package["iv"])
    ciphertext = base64.b64decode(package["data"])

    key = derive_key(password, salt, 24)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    unpadder = sym_padding.PKCS7(64).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------- RSA Hybrid ----------
def rsa_hybrid_encrypt(data: bytes) -> bytes:
    public_key = load_rsa_public_key()
    if not public_key:
        raise FileNotFoundError("RSA public key is not providedd. First generate RSA keys.")

    aes_key = os.urandom(32)
    iv = os.urandom(16)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    wrapped_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    package = {
        "type": "RSA-HYBRID",
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(package).encode("utf-8")


def rsa_hybrid_decrypt(package_bytes: bytes) -> bytes:
    private_key = load_rsa_private_key()
    if not private_key:
        raise FileNotFoundError("RSA private key is not provided. First generate RSA keys.")

    package = json.loads(package_bytes.decode("utf-8"))
    wrapped_key = base64.b64decode(package["wrapped_key"])
    iv = base64.b64decode(package["iv"])
    ciphertext = base64.b64decode(package["data"])

    aes_key = private_key.decrypt(
        wrapped_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------- Main GUI ----------
class EnpToolKitApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(WINDOW_SIZE)
        self.root.resizable(False, False)

        self.method_var = tk.StringVar(value="AES-256")
        self.mode_var = tk.StringVar(value="Text")

        self.build_ui()
        self.update_ui()

    def build_ui(self):
        tk.Label(self.root, text="ENP TOOL KIT", font=("Arial", 20, "bold")).pack(pady=8)

        top = tk.Frame(self.root)
        top.pack(pady=4)

        tk.Label(top, text="Method:", font=("Arial", 10, "bold")).grid(row=0, column=0, padx=6, pady=4)
        self.method_box = ttk.Combobox(
            top,
            textvariable=self.method_var,
            values=METHODS,
            state="readonly",
            width=18
        )
        self.method_box.grid(row=0, column=1, padx=6, pady=4)
        self.method_box.bind("<<ComboboxSelected>>", lambda e: self.update_ui())

        tk.Label(top, text="Mode:", font=("Arial", 10, "bold")).grid(row=0, column=2, padx=6, pady=4)
        self.mode_box = ttk.Combobox(
            top,
            textvariable=self.mode_var,
            values=["Text", "File"],
            state="readonly",
            width=12
        )
        self.mode_box.grid(row=0, column=3, padx=6, pady=4)
        self.mode_box.bind("<<ComboboxSelected>>", lambda e: self.update_ui())

        self.password_frame = tk.Frame(self.root)
        tk.Label(self.password_frame, text="Password:", font=("Arial", 10)).pack(side="left", padx=5)
        self.password_entry = tk.Entry(self.password_frame, width=32, show="*")
        self.password_entry.pack(side="left", padx=5)

        self.key_frame = tk.Frame(self.root)
        tk.Button(self.key_frame, text="Generate Fernet Key", width=18, command=self.gen_fernet).grid(row=0, column=0, padx=5)
        tk.Button(self.key_frame, text="Generate RSA Keys", width=18, command=self.gen_rsa).grid(row=0, column=1, padx=5)

        self.note_label = tk.Label(self.root, text="", font=("Arial", 9, "italic"))
        self.note_label.pack(pady=3)

        self.text_frame = tk.LabelFrame(self.root, text="Text Input", padx=8, pady=8)
        self.text_input = tk.Text(self.text_frame, height=7, width=82)
        self.text_input.pack()

        self.file_frame = tk.LabelFrame(self.root, text="File Input", padx=8, pady=8)
        row = tk.Frame(self.file_frame)
        row.pack(fill="x", pady=4)

        self.file_path_entry = tk.Entry(row, width=60)
        self.file_path_entry.pack(side="left", padx=5)
        tk.Button(row, text="Browse File", width=14, command=self.browse_file).pack(side="left", padx=5)

        self.file_info = tk.Label(
            self.file_frame,
            text="Output is saved at same folder.",
            font=("Arial", 9)
        )
        self.file_info.pack(anchor="w", padx=5, pady=2)

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=8)
        tk.Button(btn_frame, text="Encrypt", width=14, command=self.encrypt_action).grid(row=0, column=0, padx=8)
        tk.Button(btn_frame, text="Decrypt", width=14, command=self.decrypt_action).grid(row=0, column=1, padx=8)
        tk.Button(btn_frame, text="Clear", width=14, command=self.clear_all).grid(row=0, column=2, padx=8)

        out_frame = tk.LabelFrame(self.root, text="Output", padx=8, pady=8)
        out_frame.pack(fill="both", expand=True, padx=14, pady=8)

        self.output_text = tk.Text(out_frame, height=11, width=82)
        self.output_text.pack()

    def update_ui(self):
        method = self.method_var.get()
        mode = self.mode_var.get()

        self.password_frame.pack_forget()
        self.key_frame.pack_forget()
        self.text_frame.pack_forget()
        self.file_frame.pack_forget()

        password_methods = {"AES-128", "AES-192", "AES-256", "ChaCha20", "TripleDES"}
        key_methods = {"Fernet", "RSA-Hybrid"}

        if method in password_methods:
            self.password_frame.pack(pady=3)

        if method in key_methods:
            self.key_frame.pack(pady=3)

        if method == "Fernet":
            self.note_label.config(text="Fernet key file is used: fernet.key")
        elif method == "RSA-Hybrid":
            self.note_label.config(text="RSA-Hybrid file or text, for both practical is present.")
        elif method == "TripleDES":
            self.note_label.config(text="TripleDES is OLD, AES-256 is better.")
        elif method == "ChaCha20":
            self.note_label.config(text="ChaCha20 is fast stream cipher.")
        else:
            self.note_label.config(text="Secure password-based encryption.")

        if mode == "Text":
            self.text_frame.pack(fill="x", padx=14, pady=6)
        else:
            self.file_frame.pack(fill="x", padx=14, pady=6)

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, path)

    def gen_fernet(self):
        generate_fernet_key()
        messagebox.showinfo("Success", "fernet.key is generated.")

    def gen_rsa(self):
        generate_rsa_keys()
        messagebox.showinfo("Success", "rsa_private.pem aur rsa_public.pem is generated.")

    def clear_all(self):
        self.password_entry.delete(0, tk.END)
        self.text_input.delete("1.0", tk.END)
        self.file_path_entry.delete(0, tk.END)
        self.output_text.delete("1.0", tk.END)

    def set_output(self, text: str):
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)

    def encrypt_bytes(self, method: str, data: bytes, password: str) -> bytes:
        if method == "AES-128":
            return aes_encrypt(data, password, 128)
        if method == "AES-192":
            return aes_encrypt(data, password, 192)
        if method == "AES-256":
            return aes_encrypt(data, password, 256)
        if method == "Fernet":
            key = load_fernet_key()
            if not key:
                raise FileNotFoundError("fernet.key is not provided. First generate it.")
            return Fernet(key).encrypt(data)
        if method == "ChaCha20":
            return chacha20_encrypt(data, password)
        if method == "TripleDES":
            return tdes_encrypt(data, password)
        if method == "RSA-Hybrid":
            return rsa_hybrid_encrypt(data)
        raise ValueError("Unsupported method")

    def decrypt_bytes(self, method: str, data: bytes, password: str) -> bytes:
        if method == "AES-128" or method == "AES-192" or method == "AES-256":
            return aes_decrypt(data, password)
        if method == "Fernet":
            key = load_fernet_key()
            if not key:
                raise FileNotFoundError("fernet.key is not given.")
            return Fernet(key).decrypt(data)
        if method == "ChaCha20":
            return chacha20_decrypt(data, password)
        if method == "TripleDES":
            return tdes_decrypt(data, password)
        if method == "RSA-Hybrid":
            return rsa_hybrid_decrypt(data)
        raise ValueError("Unsupported method")

    def encrypt_action(self):
        try:
            method = self.method_var.get()
            mode = self.mode_var.get()
            password = self.password_entry.get().strip()

            if method in {"AES-128", "AES-192", "AES-256", "ChaCha20", "TripleDES"} and not password:
                messagebox.showerror("Error", "Write Password, it is compulsory.")
                return

            if mode == "Text":
                text = self.text_input.get("1.0", tk.END).strip()
                if not text:
                    messagebox.showerror("Error", "Text is not written yet.")
                    return

                result = self.encrypt_bytes(method, text.encode("utf-8"), password)
                self.set_output(result.decode("utf-8", errors="ignore") if method != "Fernet" else result.decode())

            else:
                in_file = self.file_path_entry.get().strip()
                if not in_file or not os.path.exists(in_file):
                    messagebox.showerror("Error", "Please select a Valid file.")
                    return

                data = load_bytes(in_file)
                result = self.encrypt_bytes(method, data, password)

                ext_map = {
                    "AES-128": ".aes",
                    "AES-192": ".aes",
                    "AES-256": ".aes",
                    "Fernet": ".fernet",
                    "ChaCha20": ".chacha",
                    "TripleDES": ".tdes",
                    "RSA-Hybrid": ".rhy"
                }
                out_file = default_output_path(in_file, ext_map[method])

                save_bytes(out_file, result)
                self.set_output(f"File is encrypted:\n{out_file}")
                messagebox.showinfo("Success", f"Output is saved in same folder:\n{out_file}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_action(self):
        try:
            method = self.method_var.get()
            mode = self.mode_var.get()
            password = self.password_entry.get().strip()

            if method in {"AES-128", "AES-192", "AES-256", "ChaCha20", "TripleDES"} and not password:
                messagebox.showerror("Error", "Write password first.")
                return

            if mode == "Text":
                text = self.text_input.get("1.0", tk.END).strip()
                if not text:
                    messagebox.showerror("Error", "Text is empty.")
                    return

                result = self.decrypt_bytes(method, text.encode("utf-8"), password)
                self.set_output(result.decode("utf-8", errors="replace"))

            else:
                in_file = self.file_path_entry.get().strip()
                if not in_file or not os.path.exists(in_file):
                    messagebox.showerror("Error", "Select valid file.")
                    return

                data = load_bytes(in_file)
                result = self.decrypt_bytes(method, data, password)

                out_file = default_output_path(in_file, ".dec")
                save_bytes(out_file, result)

                self.set_output(f"File decrypt ho gayi:\n{out_file}")
                messagebox.showinfo("Success", f"Output is generated at same folder:\n{out_file}")

        except InvalidToken:
            messagebox.showerror("Error", "Decryption is failed. Either Key or password is wrong.")
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = EnpToolKitApp(root)
    root.mainloop()
