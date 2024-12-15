import tkinter as tk
from tkinter import ttk, messagebox
from key import derive_key
from option import encrypt, decrypt


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Encryption Program")
        self.root.geometry("600x500")
        self.root.resizable(False, False)

        # Warna dan tema
        self.bg_color = "#f4f4f9"
        self.header_color = "#0066cc"
        self.footer_color = "#333333"
        self.text_color = "#ffffff"

        # Set background warna
        root.configure(bg=self.bg_color)

        # Header
        header = tk.Label(
            root, 
            text="Secure Encryption Program", 
            bg=self.header_color, 
            fg=self.text_color, 
            font=("Arial", 18, "bold"), 
            pady=10
        )
        header.pack(fill="x")

        # Membuat tabbed interface (Notebook)
        self.tab_control = ttk.Notebook(root)

        # Tab Enkripsi
        self.tab_encrypt = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_encrypt, text='Encrypt')

        # Tab Dekripsi
        self.tab_decrypt = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_decrypt, text='Decrypt')

        self.tab_control.pack(expand=1, fill="both")

        # Frame untuk Tab Enkripsi
        self.create_tab(self.tab_encrypt, mode="encrypt")

        # Frame untuk Tab Dekripsi
        self.create_tab(self.tab_decrypt, mode="decrypt")

        # Footer
        footer = tk.Label(
            root,
            text="Version 0.1 - Secure Encryption Project",
            bg=self.footer_color,
            fg=self.text_color,
            font=("Arial", 10),
            pady=5
        )
        footer.pack(side="bottom", fill="x")

    def create_tab(self, tab, mode):
        """Buat Form untuk Enkripsi atau Dekripsi."""
        # Input Teks
        tk.Label(tab, text="Input Text:", bg=self.bg_color, font=("Arial", 12)).pack(anchor="w", padx=20)
        input_text = tk.Text(tab, height=5, width=60)
        input_text.pack(pady=5)

        # Input Password
        tk.Label(tab, text="Password:", bg=self.bg_color, font=("Arial", 12)).pack(anchor="w", padx=20)
        password_entry = tk.Entry(tab, show="*", width=40)
        password_entry.pack(pady=5)

        # Tombol Eksekusi
        execute_button = tk.Button(
            tab, 
            text="Process", 
            command=lambda: self.process(input_text, password_entry, mode),
            bg=self.header_color, 
            fg=self.text_color, 
            font=("Arial", 12, "bold"),
            padx=10, pady=5
        )
        execute_button.pack(pady=20)

        # Output
        tk.Label(tab, text="Output:", bg=self.bg_color, font=("Arial", 12)).pack(anchor="w", padx=20)
        output_text = tk.Text(tab, height=5, width=60, state="disabled")
        output_text.pack(pady=5)

    def process(self, input_text, password_entry, mode):
        """Proses Enkripsi atau Dekripsi Berdasarkan Pilihan."""
        input_text = input_text.get("1.0", tk.END).strip()
        password = password_entry.get()

        if not input_text or not password:
            messagebox.showwarning("Warning", "Input Text and Password cannot be empty!")
            return

        key = derive_key(password)

        if mode == "encrypt":
            encrypted_text = encrypt(input_text, key)
            self.show_output(encrypted_text.hex(), input_text, mode)
        elif mode == "decrypt":
            try:
                encrypted_bytes = bytes.fromhex(input_text)
                decrypted_text = decrypt(encrypted_bytes, key)
                self.show_output(decrypted_text, input_text, mode)
            except ValueError:
                self.show_output("Invalid input! Make sure it's valid hex.", input_text, mode)

    def show_output(self, output, input_text, mode):
        """Tampilkan Output ke Text Widget."""
        # Menampilkan output pada tab yang aktif
        tab = self.tab_encrypt if mode == "encrypt" else self.tab_decrypt
        output_text = tab.winfo_children()[-1]  # Ambil widget text terakhir
        output_text.config(state="normal")
        output_text.delete("1.0", tk.END)
        output_text.insert("1.0", output)
        output_text.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()