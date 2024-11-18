from fastapi import FastAPI, File, UploadFile
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

app = FastAPI()

# Rutas y carpetas
UPLOAD_FOLDER = "uploads/"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Generar claves si no existen
if not os.path.exists("keys/private_key.pem") or not os.path.exists("keys/public_key.pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    os.makedirs("keys", exist_ok=True)

    with open("keys/private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open("keys/public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

# Endpoint para recibir archivo cifrado
@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    encrypted_file_path = UPLOAD_FOLDER + "encrypted_" + file.filename

    # Guardar archivo cifrado
    with open(encrypted_file_path, "wb") as f:
        f.write(await file.read())

    # Descifrar el archivo
    with open("keys/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None
        )

    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Guardar archivo descifrado
    decrypted_file_path = UPLOAD_FOLDER + "decrypted_" + file.filename.replace("encrypted_", "")
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    return {"message": f"Archivo {decrypted_file_path} descifrado correctamente"}
