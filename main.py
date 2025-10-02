import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from PIL import Image
import io


class CipherCanvas:
    def __init__(self, root):
        self.root = root
        self.root.title("CipherCanvas - Cryptography + Steganography")
        self.root.geometry("800x700")
        
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.aes_key = None
        self.encrypted_aes_key = None
        self.self_destruct = tk.BooleanVar()
        
        self.setup_ui()
        
    def setup_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.hide_frame = ttk.Frame(notebook)
        self.reveal_frame = ttk.Frame(notebook)
        
        notebook.add(self.hide_frame, text="Hide Secret Message")
        notebook.add(self.reveal_frame, text="Reveal Secret Message")
        
        self.setup_hide_tab()
        self.setup_reveal_tab()
        
    def setup_hide_tab(self):
        ttk.Label(self.hide_frame, text="Secret Message:", font=('Arial', 12, 'bold')).pack(pady=10)
        
        self.message_text = scrolledtext.ScrolledText(self.hide_frame, height=8, width=80)
        self.message_text.pack(padx=10, pady=5)
        
        ttk.Label(self.hide_frame, text="Select Input Image:", font=('Arial', 10)).pack(pady=5)
        
        input_frame = ttk.Frame(self.hide_frame)
        input_frame.pack(pady=5)
        
        self.input_image_label = ttk.Label(input_frame, text="No image selected")
        self.input_image_label.pack(side='left', padx=5)
        
        ttk.Button(input_frame, text="Browse Image", command=self.browse_input_image).pack(side='left', padx=5)
        
        self.use_rsa_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.hide_frame, text="Use RSA encryption for AES key", variable=self.use_rsa_var).pack(pady=5)
        
        ttk.Button(self.hide_frame, text="Hide Message in Image", command=self.hide_message, 
                  style='Accent.TButton').pack(pady=10)
        
        ttk.Label(self.hide_frame, text="Encryption Keys:", font=('Arial', 10, 'bold')).pack(pady=5)
        
        self.keys_text = scrolledtext.ScrolledText(self.hide_frame, height=6, width=80)
        self.keys_text.pack(padx=10, pady=5)
        
        ttk.Button(self.hide_frame, text="Save Keys to File", command=self.save_keys).pack(pady=5)
        
        ttk.Label(self.hide_frame, text="Status Log:", font=('Arial', 10, 'bold')).pack(pady=5)
        
        self.hide_log = scrolledtext.ScrolledText(self.hide_frame, height=8, width=80, state='disabled')
        self.hide_log.pack(padx=10, pady=5)
        
    def setup_reveal_tab(self):
        ttk.Label(self.reveal_frame, text="Select Image with Hidden Message:", 
                 font=('Arial', 12, 'bold')).pack(pady=10)
        
        input_frame = ttk.Frame(self.reveal_frame)
        input_frame.pack(pady=5)
        
        self.reveal_image_label = ttk.Label(input_frame, text="No image selected")
        self.reveal_image_label.pack(side='left', padx=5)
        
        ttk.Button(input_frame, text="Browse Image", command=self.browse_reveal_image).pack(side='left', padx=5)
        
        ttk.Label(self.reveal_frame, text="AES Key (base64):", font=('Arial', 10)).pack(pady=5)
        
        self.aes_key_entry = ttk.Entry(self.reveal_frame, width=80)
        self.aes_key_entry.pack(padx=10, pady=5)
        
        self.use_rsa_reveal_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.reveal_frame, text="Use RSA decryption", 
                       variable=self.use_rsa_reveal_var).pack(pady=5)
        
        ttk.Label(self.reveal_frame, text="RSA Private Key:", font=('Arial', 10)).pack(pady=5)
        
        self.private_key_text = scrolledtext.ScrolledText(self.reveal_frame, height=6, width=80)
        self.private_key_text.pack(padx=10, pady=5)
        
        ttk.Checkbutton(self.reveal_frame, text="Self-destruct after first read", 
                       variable=self.self_destruct).pack(pady=5)
        
        ttk.Button(self.reveal_frame, text="Reveal Secret Message", command=self.reveal_message,
                  style='Accent.TButton').pack(pady=10)
        
        ttk.Label(self.reveal_frame, text="Decrypted Message:", font=('Arial', 10, 'bold')).pack(pady=5)
        
        self.revealed_text = scrolledtext.ScrolledText(self.reveal_frame, height=8, width=80)
        self.revealed_text.pack(padx=10, pady=5)
        
        ttk.Label(self.reveal_frame, text="Status Log:", font=('Arial', 10, 'bold')).pack(pady=5)
        
        self.reveal_log = scrolledtext.ScrolledText(self.reveal_frame, height=8, width=80, state='disabled')
        self.reveal_log.pack(padx=10, pady=5)
        
    def browse_input_image(self):
        filename = filedialog.askopenfilename(
            title="Select Input Image",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if filename:
            self.input_image_path = filename
            self.input_image_label.config(text=os.path.basename(filename))
            
    def browse_reveal_image(self):
        filename = filedialog.askopenfilename(
            title="Select Image with Hidden Message",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if filename:
            self.reveal_image_path = filename
            self.reveal_image_label.config(text=os.path.basename(filename))
            
    def log_to_hide(self, message):
        self.hide_log.config(state='normal')
        self.hide_log.insert(tk.END, f"{message}\n")
        self.hide_log.see(tk.END)
        self.hide_log.config(state='disabled')
        self.root.update()
        
    def log_to_reveal(self, message):
        self.reveal_log.config(state='normal')
        self.reveal_log.insert(tk.END, f"{message}\n")
        self.reveal_log.see(tk.END)
        self.reveal_log.config(state='disabled')
        self.root.update()
        
    def generate_rsa_keys(self):
        self.log_to_hide("Generating RSA key pair...")
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        self.log_to_hide("RSA keys generated successfully")
        
    def encrypt_message(self, message):
        self.log_to_hide("Generating AES key...")
        self.aes_key = Fernet.generate_key()
        fernet = Fernet(self.aes_key)
        
        self.log_to_hide("Computing SHA-256 hash of message...")
        message_hash = hashlib.sha256(message.encode()).digest()
        
        message_with_hash = message_hash + message.encode()
        
        self.log_to_hide("Encrypting message with AES...")
        encrypted_message = fernet.encrypt(message_with_hash)
        
        if self.use_rsa_var.get():
            self.log_to_hide("Encrypting AES key with RSA public key...")
            self.encrypted_aes_key = self.rsa_public_key.encrypt(
                self.aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        else:
            self.encrypted_aes_key = None
            
        self.log_to_hide("Message encrypted successfully")
        return encrypted_message
        
    def decrypt_message(self, encrypted_message, aes_key):
        self.log_to_reveal("Decrypting message with AES key...")
        fernet = Fernet(aes_key)
        
        try:
            decrypted_data = fernet.decrypt(encrypted_message)
            
            message_hash = decrypted_data[:32]
            message = decrypted_data[32:]
            
            self.log_to_reveal("Verifying SHA-256 hash...")
            computed_hash = hashlib.sha256(message).digest()
            
            if message_hash != computed_hash:
                raise ValueError("Message integrity check failed!")
                
            self.log_to_reveal("Message integrity verified successfully")
            return message.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
            
    def hide_in_image(self, image_path, encrypted_message):
        self.log_to_hide("Loading input image...")
        img = Image.open(image_path)
        
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        pixels = list(img.getdata())
        
        message_bytes = encrypted_message
        message_length = len(message_bytes)
        
        self.log_to_hide(f"Encrypted message size: {message_length} bytes")
        
        length_bytes = message_length.to_bytes(4, byteorder='big')
        data_to_hide = length_bytes + message_bytes
        
        binary_data = ''.join(format(byte, '08b') for byte in data_to_hide)
        
        max_capacity = len(pixels) * 3
        if len(binary_data) > max_capacity:
            raise ValueError(f"Image too small! Need {len(binary_data)} bits, have {max_capacity}")
            
        self.log_to_hide("Embedding encrypted data into image using LSB steganography...")
        
        new_pixels = []
        data_index = 0
        
        for pixel in pixels:
            r, g, b = pixel
            
            if data_index < len(binary_data):
                r = (r & 0xFE) | int(binary_data[data_index])
                data_index += 1
                
            if data_index < len(binary_data):
                g = (g & 0xFE) | int(binary_data[data_index])
                data_index += 1
                
            if data_index < len(binary_data):
                b = (b & 0xFE) | int(binary_data[data_index])
                data_index += 1
                
            new_pixels.append((r, g, b))
            
        new_img = Image.new('RGB', img.size)
        new_img.putdata(new_pixels)
        
        self.log_to_hide("Saving image with hidden message as 'output.png'...")
        new_img.save('output.png', 'PNG')
        self.log_to_hide("Image saved successfully!")
        
    def extract_from_image(self, image_path):
        self.log_to_reveal("Loading image...")
        img = Image.open(image_path)
        
        if img.mode != 'RGB':
            img = img.convert('RGB')
            
        pixels = list(img.getdata())
        
        self.log_to_reveal("Extracting hidden data using LSB steganography...")
        
        binary_data = ''
        for pixel in pixels:
            r, g, b = pixel
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
            
            if len(binary_data) >= 32:
                break
                
        length = int(binary_data[:32], 2)
        self.log_to_reveal(f"Hidden message size: {length} bytes")
        
        bits_needed = 32 + (length * 8)
        
        binary_data = ''
        for pixel in pixels:
            r, g, b = pixel
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
            
            if len(binary_data) >= bits_needed:
                break
                
        length_bits = binary_data[:32]
        message_bits = binary_data[32:bits_needed]
        
        message_bytes = bytearray()
        for i in range(0, len(message_bits), 8):
            byte = message_bits[i:i+8]
            message_bytes.append(int(byte, 2))
            
        self.log_to_reveal("Hidden data extracted successfully")
        return bytes(message_bytes)
        
    def hide_message(self):
        self.hide_log.config(state='normal')
        self.hide_log.delete('1.0', tk.END)
        self.hide_log.config(state='disabled')
        
        self.keys_text.delete('1.0', tk.END)
        
        message = self.message_text.get('1.0', tk.END).strip()
        
        if not message:
            messagebox.showerror("Error", "Please enter a message to hide!")
            return
            
        if not hasattr(self, 'input_image_path'):
            messagebox.showerror("Error", "Please select an input image!")
            return
            
        try:
            if self.use_rsa_var.get():
                self.generate_rsa_keys()
                
            encrypted_message = self.encrypt_message(message)
            
            self.hide_in_image(self.input_image_path, encrypted_message)
            
            self.keys_text.insert(tk.END, "=== ENCRYPTION KEYS ===\n\n")
            self.keys_text.insert(tk.END, f"AES Key (base64):\n{base64.b64encode(self.aes_key).decode()}\n\n")
            
            if self.use_rsa_var.get():
                private_pem = self.rsa_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                public_pem = self.rsa_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                self.keys_text.insert(tk.END, f"RSA Private Key:\n{private_pem.decode()}\n")
                self.keys_text.insert(tk.END, f"RSA Public Key:\n{public_pem.decode()}\n")
                self.keys_text.insert(tk.END, f"Encrypted AES Key (base64):\n{base64.b64encode(self.encrypted_aes_key).decode()}\n")
                
            messagebox.showinfo("Success", "Message hidden successfully!\nOutput saved as 'output.png'")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide message: {str(e)}")
            self.log_to_hide(f"ERROR: {str(e)}")
            
    def reveal_message(self):
        self.reveal_log.config(state='normal')
        self.reveal_log.delete('1.0', tk.END)
        self.reveal_log.config(state='disabled')
        
        self.revealed_text.delete('1.0', tk.END)
        
        if not hasattr(self, 'reveal_image_path'):
            messagebox.showerror("Error", "Please select an image!")
            return
            
        aes_key_input = self.aes_key_entry.get().strip()
        
        if not aes_key_input:
            messagebox.showerror("Error", "Please enter the AES key!")
            return
            
        try:
            if self.use_rsa_reveal_var.get():
                private_key_pem = self.private_key_text.get('1.0', tk.END).strip()
                
                if not private_key_pem:
                    messagebox.showerror("Error", "Please enter the RSA private key!")
                    return
                    
                self.log_to_reveal("Loading RSA private key...")
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=None
                )
                
                self.log_to_reveal("Decrypting AES key with RSA private key...")
                encrypted_aes_key = base64.b64decode(aes_key_input)
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            else:
                aes_key = base64.b64decode(aes_key_input)
                
            encrypted_message = self.extract_from_image(self.reveal_image_path)
            
            decrypted_message = self.decrypt_message(encrypted_message, aes_key)
            
            self.revealed_text.insert(tk.END, decrypted_message)
            
            self.log_to_reveal("Message revealed successfully!")
            
            if self.self_destruct.get():
                self.log_to_reveal("SELF-DESTRUCT: Clearing extracted message...")
                self.root.after(3000, self.clear_revealed_message)
                
            messagebox.showinfo("Success", "Message revealed successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reveal message: {str(e)}")
            self.log_to_reveal(f"ERROR: {str(e)}")
            
    def clear_revealed_message(self):
        self.revealed_text.delete('1.0', tk.END)
        self.revealed_text.insert(tk.END, "[Message deleted - self-destruct activated]")
        
    def save_keys(self):
        keys_content = self.keys_text.get('1.0', tk.END).strip()
        
        if not keys_content:
            messagebox.showwarning("Warning", "No keys to save!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            with open(filename, 'w') as f:
                f.write(keys_content)
            messagebox.showinfo("Success", f"Keys saved to {filename}")


def main():
    root = tk.Tk()
    app = CipherCanvas(root)
    root.mainloop()


if __name__ == "__main__":
    main()
