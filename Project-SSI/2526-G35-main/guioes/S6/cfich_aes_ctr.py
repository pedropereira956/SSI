import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

    # Gerar NONCE aleatório
    nonce = os.urandom(16)

    # Cifrar — CTR não precisa de padding!
    cipher = Cipher(algorithms.AES(chave), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    criptograma = encryptor.update(texto) + encryptor.finalize()

    # Guardar NONCE + criptograma
    with open(fich + '.enc', 'wb') as f:
        f.write(nonce + criptograma)
    print(f"Ficheiro cifrado: {fich}.enc")

def dec(fich, fkey):
    with open(fkey, 'rb') as f:
        chave = f.read()
    with open(fich, 'rb') as f:
        dados = f.read()

    # Separar NONCE do criptograma
    nonce       = dados[:16]
    criptograma = dados[16:]

    # Decifrar
    cipher = Cipher(algorithms.AES(chave), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    texto = decryptor.update(criptograma) + decryptor.finalize()

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
