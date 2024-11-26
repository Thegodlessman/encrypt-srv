import os
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Configuración
PRIVATE_KEY_PATH = "servidor/keys/private_key.pem"  # Clave privada del servidor
OUTPUT_PATH = "servidor/output/decrypted_file.docx"

app = Flask(__name__)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        return "Este endpoint permite GET"

    if 'file' not in request.files:
        return jsonify({"error": "No se envió ningún archivo."}), 400

    file = request.files['file']
    encrypted_data = file.read()

    # Cargar clave privada del servidor
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Descifrar en bloques
    BLOCK_SIZE = 256  # El tamaño de bloque debe coincidir con el tamaño de la clave RSA
    decrypted_data = b""  # Almacena el archivo descifrado
    for i in range(0, len(encrypted_data), BLOCK_SIZE):
        block = encrypted_data[i:i + BLOCK_SIZE]
        decrypted_data += private_key.decrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Guardar archivo descifrado
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    return jsonify({"message": "Archivo procesado y descifrado con éxito."}), 200

if __name__ == '__main__':
    # El servidor necesita HTTPS para cifrado, utilizando los certificados de mkcert
    app.run(ssl_context=("certificados/localhost.pem", "certificados/localhost-key.pem"), host='localhost', port=5000)
