import json
import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

import requests
from PIL import Image, ImageTk

from crypto_utils import (
    b64e,
    load_public_key_from_pem,
    rsa_encrypt_oaep,
    aesgcm_encrypt,
    hmac_sha256
)


# ---------------- DATA ---------------- #

@dataclass
class Student:
    student_id: str
    name: str
    to: str
    message: str
    timestamp: str


class SecureMessengerGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        # Light blue ttk styles (ADD THIS)
        style = ttk.Style(self)
        style.configure("Blue.TFrame", background="#EAF4FF")
        style.configure("Blue.TLabelframe", background="#EAF4FF")
        style.configure(
            "Blue.TLabelframe.Label",
            background="#EAF4FF",
            font=("Segoe UI", 10, "bold")
        )

        self.title("💙 Secure Messenger — Cinnamoroll Edition")
        self.geometry("980x620")
        self.configure(bg="#F7FBFF")

        # session
        self.public_key_pem = None
        self.aes_key = None

        # vars
        self.server_var = tk.StringVar(value="http://127.0.0.1:8000")
        self.api_key_var = tk.StringVar(value="Cinnamoroll")
        self.client_id_var = tk.StringVar(value="alicia")
        self.to_var = tk.StringVar(value="bob")

        self._build_ui()


    # ---------------- UI ---------------- #

    def _build_ui(self):
        main = ttk.Frame(self, padding=12, style="Blue.TFrame")
        main.pack(fill="both", expand=True)

        self._load_banner(main)

        # connection
        conn = ttk.LabelFrame(main, text="Connection", padding=10, style="Blue.TLabelframe")
        conn.pack(fill="x", pady=8)

        ttk.Label(conn, text="Server").grid(row=0, column=0, sticky="w")
        ttk.Entry(conn, textvariable=self.server_var, width=40).grid(row=0, column=1)

        ttk.Label(conn, text="Client ID").grid(row=1, column=0, sticky="w")
        ttk.Entry(conn, textvariable=self.client_id_var, width=20).grid(row=1, column=1, sticky="w")

        ttk.Label(conn, text="API Key").grid(row=2, column=0, sticky="w")
        ttk.Entry(conn, textvariable=self.api_key_var, width=40, show="*").grid(row=2, column=1)

        ttk.Button(
            conn,
            text="Step 1: Handshake",
            command=self.handshake_clicked
        ).grid(row=3, column=0, columnspan=2, pady=8, sticky="ew")

        # message
        msg = ttk.LabelFrame(main, text="Message", padding=10, style="Blue.TLabelframe")
        msg.pack(fill="x")

        ttk.Label(msg, text="To").pack(anchor="w")
        ttk.Entry(msg, textvariable=self.to_var, width=20).pack(anchor="w")

        self.message_text = tk.Text(msg, height=4)
        self.message_text.pack(fill="x", pady=6)
        self.message_text.insert("1.0", "Hello from the Secure Messenger 💙")

        self.send_btn = ttk.Button(
            main,
            text="Step 2: Encrypt + Send",
            command=self.send_clicked,
            state="disabled"
        )
        self.send_btn.pack(fill="x", pady=8)

        # history
        history = ttk.LabelFrame(main, text="Message History", padding=10, style="Blue.TLabelframe")
        history.pack(fill="both", expand=True)

        cols = ("from", "to", "time", "preview", "status")
        self.history = ttk.Treeview(history, columns=cols, show="headings")

        for c in cols:
            self.history.heading(c, text=c.capitalize())

        self.history.column("from", width=90)
        self.history.column("to", width=90)
        self.history.column("time", width=170)
        self.history.column("preview", width=380)
        self.history.column("status", width=140)

        scroll = ttk.Scrollbar(history, command=self.history.yview)
        self.history.configure(yscrollcommand=scroll.set)

        self.history.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    # ---------------- helpers ---------------- #

    def _load_banner(self, parent):
        path = os.path.join(os.path.dirname(__file__), "assets", "cinnamorollBlueHeader.jpg")

        banner_frame = tk.Frame(parent, bg="#F7FBFF", height=140)
        banner_frame.pack(fill="x")
        banner_frame.pack_propagate(False)  # IMPORTANT: stop resizing

        if os.path.exists(path):
            img = Image.open(path)

            MAX_WIDTH = 900
            MAX_HEIGHT = 120

            w, h = img.size
            scale = min(MAX_WIDTH / w, MAX_HEIGHT / h)
            new_size = (int(w * scale), int(h * scale))

            img = img.resize(new_size, Image.LANCZOS)
            self.banner_img = ImageTk.PhotoImage(img)

            tk.Label(
                banner_frame,
                image=self.banner_img,
                bg="#F7FBFF"
            ).pack(expand=True)

        else:
            tk.Label(
                banner_frame,
                text="💙 Secure Messenger 💙",
                bg="#F7FBFF",
                font=("Segoe UI", 18, "bold")
            ).pack(expand=True)

    def _now(self):
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def _add_row(self, f, t, msg, status):
        self.history.insert(
            "",
            "end",
            values=(f, t, self._now(), msg[:60], status)
        )

    def _headers(self):
        return {"X-API-Key": self.api_key_var.get()}

    # ---------------- networking ---------------- #

    def handshake_clicked(self):
        threading.Thread(target=self._do_handshake, daemon=True).start()

    def _do_handshake(self):
        try:
            r = requests.get(f"{self.server_var.get()}/public-key")
            r.raise_for_status()

            self.public_key_pem = r.json()["public_key_pem"]
            self.aes_key = os.urandom(32)

            pub = load_public_key_from_pem(self.public_key_pem)
            enc = rsa_encrypt_oaep(pub, self.aes_key)

            requests.post(
                f"{self.server_var.get()}/handshake",
                json={"client_id": self.client_id_var.get(), "enc_key": b64e(enc)},
                headers=self._headers()
            ).raise_for_status()

            self.send_btn.config(state="normal")
            self._add_row("system", "-", "Handshake successful", "OK")

        except Exception as e:
            messagebox.showerror("Handshake failed", str(e))

    def send_clicked(self):
        threading.Thread(target=self._do_send, daemon=True).start()

    def _do_send(self):
        row_id = None
        try:
            msg = self.message_text.get("1.0", "end").strip()
            to_id = self.to_var.get().strip()
            from_id = self.client_id_var.get().strip()

            self._add_row(from_id, to_id, msg, "Sending…")

            student = Student(
                "amp7777",
                "Alicia Peters",
                to_id,
                msg,
                datetime.utcnow().isoformat() + "Z"
            )

            data = json.dumps(asdict(student)).encode()
            nonce, ct, tag = aesgcm_encrypt(self.aes_key, data)
            mac = hmac_sha256(self.aes_key, nonce + ct + tag)

            requests.post(
                f"{self.server_var.get()}/message",
                json={
                    "client_id": from_id,
                    "payload_json": "student",
                    "nonce": b64e(nonce),
                    "ciphertext": b64e(ct),
                    "tag": b64e(tag),
                    "hmac": b64e(mac),
                },
                headers=self._headers()
            ).raise_for_status()

            self._add_row(from_id, to_id, msg, "Sent ✅")

        except Exception as e:
            messagebox.showerror("Send failed", str(e))


# ---------------- run ---------------- #

if __name__ == "__main__":
    SecureMessengerGUI().mainloop()
