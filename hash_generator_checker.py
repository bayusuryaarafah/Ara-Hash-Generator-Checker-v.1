import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import hashlib

class HashGeneratorCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ara-Hash Generator & Checker v.1")
        self.geometry("900x500")
        #Author: Bayu S. Arafah

        self.tab_control = ttk.Notebook(self)
        self.tab_control.pack(expand=True, fill="both")

        self.frame_generator = ttk.Frame(self.tab_control)
        self.tab_control.add(self.frame_generator, text="Generator")

        self.frame_checker = ttk.Frame(self.tab_control)
        self.tab_control.add(self.frame_checker, text="Checker")

        self.frame_status = ttk.Frame(self.tab_control)
        self.tab_control.add(self.frame_status, text="History")

        self.file_hashes = {}  # Dictionary to store file paths and their corresponding hash values

        self.create_generator_frame()
        self.create_checker_frame()
        self.create_status_frame()

    def create_generator_frame(self):
        self.frame_generator.columnconfigure(0, weight=1)
        self.frame_generator.columnconfigure(1, weight=1)

        label_generator = ttk.Label(self.frame_generator, text="Generator")
        label_generator.grid(row=0, column=0, columnspan=2, pady=10)
        label_algorithm_generator = ttk.Label(self.frame_generator, text="Pilih Algoritma:")
        label_algorithm_generator.grid(row=1, column=0, columnspan=2)

        self.generator_var = tk.StringVar()
        self.generator_var.set("MD5")

        options = ["MD5", "SHA1", "SHA256", "SHA512"]
        dropdown_generator = ttk.Combobox(self.frame_generator, textvariable=self.generator_var, values=options, state="readonly")
        dropdown_generator.grid(row=3, column=0, columnspan=2, pady=10)

        button_upload_generator = ttk.Button(self.frame_generator, text="Upload File", command=self.upload_file_generator)
        button_upload_generator.grid(row=4, column=0, columnspan=2)

        self.textbox_generator = tk.Text(self.frame_generator, height=10, width=70)
        self.textbox_generator.grid(row=5, column=0, columnspan=2)

        button_generate = ttk.Button(self.frame_generator, text="Generate", command=self.generate_hash)
        button_generate.grid(row=6, column=0, columnspan=2, pady=10)

    def create_checker_frame(self):
        self.frame_checker.columnconfigure(0, weight=1)
        self.frame_checker.columnconfigure(1, weight=1)

        label_checker = ttk.Label(self.frame_checker, text="Checker")
        label_checker.grid(row=0, column=0, columnspan=2, pady=10)

        label_algorithm_checker = ttk.Label(self.frame_checker, text="Pilih Algoritma:")
        label_algorithm_checker.grid(row=1, column=0, columnspan=2)

        self.checker_var = tk.StringVar()
        self.checker_var.set("MD5")

        options = ["MD5", "SHA1", "SHA256", "SHA512"]
        dropdown_checker = ttk.Combobox(self.frame_checker, textvariable=self.checker_var, values=options, state="readonly")
        dropdown_checker.grid(row=2, column=0, columnspan=2, pady=10)

        button_upload_checker = ttk.Button(self.frame_checker, text="Upload File", command=self.upload_file_checker)
        button_upload_checker.grid(row=3, column=0, columnspan=2)

        label_input_hash = ttk.Label(self.frame_checker, text="Masukkan Hash:")
        label_input_hash.grid(row=4, column=0, columnspan=2, pady=10)

        self.input_hash_entry = ttk.Entry(self.frame_checker, width=70)
        self.input_hash_entry.grid(row=5, column=0, columnspan=2)

        button_check = ttk.Button(self.frame_checker, text="Check", command=self.check_hash)
        button_check.grid(row=6, column=0, columnspan=2, pady=10)

        self.status_label = ttk.Label(self.frame_checker, text="", font=("Arial", 16))
        self.status_label.grid(row=7, column=0, columnspan=2)

    def create_status_frame(self):
        self.frame_status.columnconfigure(0, weight=1)
        self.frame_status.columnconfigure(1, weight=1)

        label_status = ttk.Label(self.frame_status, text="History")
        label_status.grid(row=0, column=0, columnspan=4, pady=10)

        self.status_table = ttk.Treeview(self.frame_status, columns=("File", "Hash", "Input Hash", "Status"), show="headings")
        self.status_table.heading("File", text="File")
        self.status_table.heading("Hash", text="Hash")
        self.status_table.heading("Input Hash", text="Input Hash")
        self.status_table.heading("Status", text="Status")
        self.status_table.column("File", width=400)
        self.status_table.column("Hash", width=200)
        self.status_table.column("Input Hash", width=200)
        self.status_table.column("Status", width=150)
        self.status_table.grid(row=1, column=0, columnspan=4, padx=10)

    def upload_file_generator(self):
        file_path = filedialog.askopenfilename()
        self.generator_file_path = file_path

    def upload_file_checker(self):
        file_path = filedialog.askopenfilename()
        self.checker_file_path = file_path

    def generate_hash(self):
        algorithm = self.generator_var.get()
        file_path = self.generator_file_path

        if not file_path:
            self.textbox_generator.insert(tk.END, "Mohon unggah file terlebih dahulu.\n")
            return

        try:
            with open(file_path, "rb") as file:
                content = file.read()
                hash_value = hashlib.new(algorithm, content).hexdigest()
                self.textbox_generator.insert(tk.END, f"Hash value ({algorithm}): {hash_value}\n")
                self.add_status_row(file_path, hash_value, "", "")

        except IOError:
            self.textbox_generator.insert(tk.END, "Terjadi kesalahan saat membaca file.\n")

    def check_hash(self):
        algorithm = self.checker_var.get()
        file_path = self.checker_file_path
        input_hash = self.input_hash_entry.get()

        if not file_path:
            self.status_label.config(text="Mohon unggah file terlebih dahulu.", foreground="red")
            return

        try:
            with open(file_path, "rb") as file:
                content = file.read()
                hash_value = hashlib.new(algorithm, content).hexdigest()

                if hash_value == input_hash:
                    self.status_label.config(text="Status: Cocok", foreground="green")
                    status = "Cocok"
                else:
                    self.status_label.config(text="Status: Tidak Cocok", foreground="red")
                    status = "Tidak Cocok"
                self.add_status_row(file_path, hash_value, input_hash, status)

        except IOError:
            self.status_label.config(text="Terjadi kesalahan saat membaca file.", foreground="red")

    def add_status_row(self, file_path, hash_value, input_hash, status):
        self.status_table.insert("", tk.END, values=(file_path, hash_value, input_hash, status))

if __name__ == "__main__":
    app = HashGeneratorCheckerApp()
    app.mainloop()