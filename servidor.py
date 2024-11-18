from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Configuración
INPUT_FILE = "archivos/encrypted_documento.bin"
OUTPUT_FILE = "archivos/descifrado_documento.docx"
BLOCK_SIZE = 256  # Tamaño del bloque cifrado para RSA 2048

# Leer la clave privada
with open("keys/private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

# Leer el archivo cifrado
with open(INPUT_FILE, "rb") as enc_file:
    encrypted_data = enc_file.read()

# Dividir el archivo cifrado en bloques
encrypted_blocks = [encrypted_data[i:i + BLOCK_SIZE] for i in range(0, len(encrypted_data), BLOCK_SIZE)]

# Descifrar cada bloque con RSA
decrypted_blocks = []
for block in encrypted_blocks:
    try:
        decrypted_block = private_key.decrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
        decrypted_blocks.append(decrypted_block)
    except ValueError as e:
        print(f"Error al descifrar un bloque: {e}")
        exit(1)

# Unir los bloques descifrados y guardar el archivo descifrado
with open(OUTPUT_FILE, "wb") as dec_file:
    for decrypted_block in decrypted_blocks:
        dec_file.write(decrypted_block)

print("Archivo `.docx` descifrado correctamente.")
