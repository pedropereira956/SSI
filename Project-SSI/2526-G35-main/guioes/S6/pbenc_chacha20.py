import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import getpass

def derivar_chave(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # algoritmo de hash
        length=32,                  # 32 bytes = chave ChaCha20
        salt=salt,
        iterations=480000           # valor recomendado — torna força bruta lenta!
    )
    return kdf.derive(password.encode())

def enc(fich):
    # Ler password do stdin
    password = getpass.getpass("Password: ")

    with open(fich, 'rb') as f:
        texto = f.read()

    # Gerar salt e NONCE aleatórios
    salt  = os.urandom(16)
    nonce = os.urandom(16)

    # Derivar chave a partir da password
    chave = derivar_chave(password, salt)

    # Cifrar
    cipher = Cipher(algorithms.ChaCha20(chave, nonce), mode=None)
    criptograma = cipher.encryptor().update(texto)

    # Guardar salt + nonce + criptograma
    with open(fich + '.enc', 'wb') as f:
        f.write(salt + nonce + criptograma)
    print(f"Ficheiro cifrado: {fich}.enc")

def dec(fich):
    # Ler password do stdin
    password = getpass.getpass("Password: ")

    with open(fich, 'rb') as f:
        dados = f.read()

    # Separar salt, nonce e criptograma
    salt        = dados[:16]
    nonce       = dados[16:32]
    criptograma = dados[32:]

    # Derivar chave a partir da password
    chave = derivar_chave(password, salt)

    # Decifrar
    cipher = Cipher(algorithms.ChaCha20(chave, nonce), mode=None)
    texto = cipher.decryptor().update(criptograma)

    with open(fich + '.dec', 'wb') as f:
        f.write(texto)
    print(f"Ficheiro decifrado: {fich}.dec")

# Ler argumentos
operacao = sys.argv[1]

if operacao == "enc":
    enc(sys.argv[2])
elif operacao == "dec":
    dec(sys.argv[2])
