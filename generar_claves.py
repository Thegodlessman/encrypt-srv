import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Función para generar claves RSA
def generar_claves():
    # Generar clave privada
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Derivar clave pública
    clave_publica = clave_privada.public_key()

    # Serializar clave privada
    private_pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializar clave pública
    public_pem = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

# Función para guardar claves en las carpetas correspondientes
def guardar_claves(private_pem, public_pem):
    # Rutas de las carpetas
    servidor_keys_path = os.path.join("servidor", "keys")
    cliente_keys_path = os.path.join("cliente", "keys")

    # Crear carpetas si no existen
    os.makedirs(servidor_keys_path, exist_ok=True)
    os.makedirs(cliente_keys_path, exist_ok=True)

    # Guardar clave privada en el servidor
    with open(os.path.join(servidor_keys_path, "private_key.pem"), "wb") as private_file:
        private_file.write(private_pem)
    print(f"Clave privada guardada en: {os.path.join(servidor_keys_path, 'private_key.pem')}")

    # Guardar clave pública en el servidor
    with open(os.path.join(servidor_keys_path, "public_key.pem"), "wb") as public_file:
        public_file.write(public_pem)
    print(f"Clave pública (servidor) guardada en: {os.path.join(servidor_keys_path, 'public_key.pem')}")

    # Guardar clave pública en el cliente
    with open(os.path.join(cliente_keys_path, "public_key.pem"), "wb") as public_file:
        public_file.write(public_pem)
    print(f"Clave pública (cliente) guardada en: {os.path.join(cliente_keys_path, 'public_key.pem')}")

# Punto de entrada principal
if __name__ == "__main__":
    print("Generando claves RSA...")
    private_key, public_key = generar_claves()
    guardar_claves(private_key, public_key)
    print("¡Claves generadas y guardadas con éxito!")
