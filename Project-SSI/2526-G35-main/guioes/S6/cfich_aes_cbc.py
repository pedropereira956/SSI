import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def setup(fkey):
    chave = os.urandom(32)  # 32 bytes para AES-256
    with open(fkey, 'wb') as f:
        f.write(chave)
    print(f"Chave gerada em: {fkey}")

def enc(fich, fkey):
    with open(fkey, 'rb') as f:
        chave = f.read()
    with open(fich, 'rb') as f:
        texto = f.read()

    # Padding — CBC precisa de múltiplos de 16 bytes!
    padder = padding.PKCS7(128).padder()
    texto_padded = padder.update(texto) + padder.finalize()

    # Gerar IV aleatório
    iv = os.urandom(16)

    # Cifrar
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    criptograma = encryptor.update(texto_padded) + encryptor.finalize()

    # Guardar IV + criptograma
    with open(fich + '.enc', 'wb') as f:
        f.write(iv + criptograma)
    print(f"Ficheiro cifrado: {fich}.enc")

def dec(fich, fkey):
    with open(fkey, 'rb') as f:
        chave = f.read()
    with open(fich, 'rb') as f:
        dados = f.read()

    # Separar IV do criptograma
    iv          = dados[:16]
    criptograma = dados[16:]

    # Decifrar
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    texto_padded = decryptor.update(criptograma) + decryptor.finalize()

    # Remover padding
    unpadder = padding.PKCS7(128).unpadder()
    texto = unpadder.update(texto_padded) + unpadder.finalize()

    with open(fich + '.dec', 'wb') as f:
        f.write(texto)
    print(f"Ficheiro decifrado: {fich}.dec")

# Ler argumentos
operacao = sys.argv[1]

if operacao == "setup":
    setup(sys.argv[2])
elif operacao == "enc":
    enc(sys.argv[2], sys.argv[3])
elif operacao == "dec":
    dec(sys.argv[2], sys.argv[3])
