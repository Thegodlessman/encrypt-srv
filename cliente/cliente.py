import os
import tkinter as tk
from tkinter import filedialog
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Configuración
SERVER_PUBLIC_KEY_PATH = "../servidor/keys/public_key.pem"  # Ruta correcta del archivo de clave pública del servidor
ENCRYPTED_FILE_PATH = "output/encrypted_file.enc"
SERVER_URL = "https://localhost:5000/upload"

# Tamaño de bloque máximo para RSA (en bytes)
BLOCK_SIZE = 190  # 2048 bits (RSA key size) / 8 = 256 bytes, pero el tamaño real del bloque es más pequeño

def select_and_encrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("Word Documents", "*.docx")])
    if not file_path:
        return

    # Validar que sea un archivo Word
    if not file_path.endswith(".docx"):
        result_label.config(text="El archivo debe ser un documento Word (.docx).")
        return

    # Leer contenido del archivo
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Cargar clave pública del servidor
    if not os.path.exists(SERVER_PUBLIC_KEY_PATH):
        result_label.config(text=f"Error: El archivo de clave pública no se encuentra en {SERVER_PUBLIC_KEY_PATH}")
        return
    
    with open(SERVER_PUBLIC_KEY_PATH, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Dividir archivo en bloques y cifrar
    blocks = [file_data[i:i + BLOCK_SIZE] for i in range(0, len(file_data), BLOCK_SIZE)]
    encrypted_data = b""  # Almacena los datos cifrados
    for block in blocks:
        try:
            encrypted_data += public_key.encrypt(
                block,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError as e:
            result_label.config(text=f"Error al cifrar el archivo: {e}")
            print(e)
            return

    # Guardar archivo cifrado
    os.makedirs(os.path.dirname(ENCRYPTED_FILE_PATH), exist_ok=True)
    with open(ENCRYPTED_FILE_PATH, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    # Enviar al servidor utilizando el certificado de mkcert para verificar la conexión HTTPS
    with open(ENCRYPTED_FILE_PATH, "rb") as encrypted_file:
        response = requests.post(SERVER_URL, files={"file": encrypted_file}, 
                                verify=False)  # Usar el archivo certificado mkcert
    
        if response.status_code == 200:
            result_label.config(text="Archivo enviado y procesado exitosamente.")
        else:
            result_label.config(text=f"Error: {response.status_code} - {response.text}")

# Interfaz gráfica
root = tk.Tk()
root.title("Cliente de Cifrado")

frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

title_label = tk.Label(frame, text="Seleccione un archivo Word para cifrar:", font=("Arial", 14))
title_label.pack(pady=10)

select_button = tk.Button(frame, text="Seleccionar archivo", command=select_and_encrypt_file, font=("Arial", 12))
select_button.pack(pady=5)

result_label = tk.Label(frame, text="", font=("Arial", 12))
result_label.pack(pady=10)

root.mainloop()
