import customtkinter as ctk
import webbrowser
from tkinter import messagebox, filedialog
from Cryptodome.Cipher import AES, DES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import base64

# Initialize CustomTkinter
ctk.set_appearance_mode("dark")  # Dark Mode
ctk.set_default_color_theme("blue")

class EncryptionApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Text Encryption App")
        self.geometry("600x500")
        self.resizable(False, False)

        # 🔹 Main Frame
        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # 🔹 Title Label
        self.label_title = ctk.CTkLabel(self.main_frame, text="🔒 Secure Text Encryption", font=("Arial", 22, "bold"))
        self.label_title.pack(pady=10)

        # 🔹 Input Section
        self.label_input = ctk.CTkLabel(self.main_frame, text="Enter text:", font=("Arial", 12))
        self.label_input.pack(pady=5)

        self.text_input = ctk.CTkTextbox(self.main_frame, height=80, width=500, corner_radius=10)
        self.text_input.pack(pady=5)

        # 🔹 Algorithm Selection
        self.label_select = ctk.CTkLabel(self.main_frame, text="Choose Encryption:", font=("Arial", 12))
        self.label_select.pack(pady=5)

        self.algorithms = ["AES", "DES", "RSA"]
        self.selected_algorithm = ctk.StringVar(value=self.algorithms[0])
        self.dropdown = ctk.CTkComboBox(self.main_frame, values=self.algorithms, variable=self.selected_algorithm)
        self.dropdown.pack(pady=5)

        # 🔹 Buttons Frame (Encrypt & Decrypt)
        self.button_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.button_frame.pack(pady=10)

        self.encrypt_button = ctk.CTkButton(self.button_frame, text="🔐 Encrypt", command=self.encrypt_text, width=100)
        self.encrypt_button.grid(row=0, column=0, padx=10)

        self.decrypt_button = ctk.CTkButton(self.button_frame, text="🔓 Decrypt", command=self.decrypt_text, width=100)
        self.decrypt_button.grid(row=0, column=1, padx=10)

        # 🔹 Output Section
        self.label_output = ctk.CTkLabel(self.main_frame, text="Encrypted Output:", font=("Arial", 12))
        self.label_output.pack(pady=5)

        self.text_output = ctk.CTkTextbox(self.main_frame, height=80, width=500, corner_radius=10)
        self.text_output.pack(pady=5)

        # 🔹 Key Management
        self.key_button = ctk.CTkButton(self.main_frame, text="🔑 Generate Key", command=self.generate_key, width=150)
        self.key_button.pack(pady=10)

        # 🔹 Developer Credit (Clickable)
        self.developer_label = ctk.CTkLabel(
            self.main_frame, text="Developer: Ajay-710", text_color="lightblue",
            font=("Arial", 10), cursor="hand2"
        )
        self.developer_label.pack(pady=5)
        self.developer_label.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/Ajay-710"))

    def encrypt_text(self):
        text = self.text_input.get("1.0", "end").strip()
        algo = self.selected_algorithm.get()

        if algo == "AES":
            key = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(text.encode())
            encrypted_text = base64.b64encode(cipher.nonce + tag + ciphertext).decode()

        elif algo == "DES":
            key = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_ECB)
            padded_text = text + (8 - len(text) % 8) * " "
            encrypted_text = base64.b64encode(cipher.encrypt(padded_text.encode())).decode()

        elif algo == "RSA":
            key = RSA.generate(2048)
            public_key = key.publickey().export_key()
            cipher = key.publickey().encrypt(text.encode(), 32)
            encrypted_text = base64.b64encode(cipher[0]).decode()

        self.text_output.delete("1.0", "end")
        self.text_output.insert("1.0", encrypted_text)

    def decrypt_text(self):
        messagebox.showinfo("Info", "Decryption feature coming soon! \nVisit: https://github.com/Ajay-710")

    def generate_key(self):
        algo = self.selected_algorithm.get()
        if algo == "AES":
            key = get_random_bytes(16)
        elif algo == "DES":
            key = get_random_bytes(8)
        elif algo == "RSA":
            key = RSA.generate(2048).export_key()

        file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
        if file_path:
            with open(file_path, "wb") as f:
                f.write(key)
            messagebox.showinfo("Success", "Key saved successfully!")

if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()
