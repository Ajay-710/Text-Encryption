import customtkinter as ctk
import webbrowser
from tkinter import messagebox, filedialog
from Cryptodome.Cipher import AES, DES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import base64, os
root = ctk.CTk()

# Initialize CustomTkinter
ctk.set_appearance_mode("dark")  # Default Dark Mode
ctk.set_default_color_theme("blue")

class EncryptionApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Text Encryption App")
        self.geometry("600x500")
        self.resizable(False, False)
        
        # Title Label
        self.label_title = ctk.CTkLabel(self, text="Text Encryption Tool", font=("Arial", 20, "bold"))
        self.label_title.pack(pady=10)
        
        # Input Text Label
        self.label_input = ctk.CTkLabel(self, text="Enter text to encrypt here:", font=("Arial", 12))
        self.label_input.pack(pady=5)
        
        # Input Text Box
        self.text_input = ctk.CTkTextbox(self, height=100, width=500)
        self.text_input.pack(pady=5)
        
        # Algorithm Selection
        self.label_select = ctk.CTkLabel(self, text="Select encryption type:", font=("Arial", 12))
        self.label_select.pack(pady=5)
        
        self.algorithms = ["AES", "DES", "RSA"]
        self.selected_algorithm = ctk.StringVar(value=self.algorithms[0])
        self.dropdown = ctk.CTkComboBox(self, values=self.algorithms, variable=self.selected_algorithm)
        self.dropdown.pack(pady=5)
        
        # Encrypt & Decrypt Buttons
        self.encrypt_button = ctk.CTkButton(self, text="Encrypt", command=self.encrypt_text)
        self.encrypt_button.pack(pady=5)
        
        self.decrypt_button = ctk.CTkButton(self, text="Decrypt", command=self.decrypt_text)
        self.decrypt_button.pack(pady=5)
        
        # Output Text Box
        self.text_output = ctk.CTkTextbox(self, height=100, width=500)
        self.text_output.pack(pady=5)
        
        # Key Management Buttons
        self.key_button = ctk.CTkButton(self, text="Generate Key", command=self.generate_key)
        self.key_button.pack(pady=5)
        
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
        messagebox.showinfo("Info", "Decryption feature coming soon! \n" "https://github.com/Ajay-710" )
    
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
