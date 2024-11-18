from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Configuración
FILE_PATH = "archivos/archivo.docx"
OUTPUT_FILE = "archivos/encrypted_documento.bin"
BLOCK_SIZE = 190  # Reducido para garantizar compatibilidad con OAEP y SHA256

# Leer el archivo `.docx` como binario
with open(FILE_PATH, "rb") as file:
    file_data = file.read()

# Dividir el archivo en bloques de tamaño adecuado
blocks = [file_data[i:i + BLOCK_SIZE] for i in range(0, len(file_data), BLOCK_SIZE)]

# Leer la clave pública
with open("keys/public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

# Cifrar cada bloque con RSA
encrypted_blocks = []
for block in blocks:
    try:
        encrypted_block = public_key.encrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
        encrypted_blocks.append(encrypted_block)
    except ValueError as e:
        print(f"Error al cifrar un bloque: {e}")
        exit(1)

# Guardar el archivo cifrado como binario
with open(OUTPUT_FILE, "wb") as enc_file:
    for encrypted_block in encrypted_blocks:
        enc_file.write(encrypted_block)

print("Archivo `.docx` cifrado correctamente.")
