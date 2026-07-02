import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
import getpass

def derivar_chaves(password, salt):
    # Derivar 48 bytes — 32 para AES-CTR + 16 para HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,           # 32 + 16 bytes!
        salt=salt,
        iterations=480000
    )
    chaves = kdf.derive(password.encode())
    chave_aes  = chaves[:32]   # primeiros 32 bytes → AES
    chave_hmac = chaves[32:]   # últimos 16 bytes → HMAC
    return chave_aes, chave_hmac

def enc(fich):
    password = getpass.getpass("Password: ")

    with open(fich, 'rb') as f:
        texto = f.read()

    # Gerar salt e nonce
    salt  = os.urandom(16)
    nonce = os.urandom(16)

    # Derivar duas chaves
    chave_aes, chave_hmac = derivar_chaves(password, salt)

    # 1. Cifrar (AES-CTR)
    cipher = Cipher(algorithms.AES(chave_aes), modes.CTR(nonce))
    criptograma = cipher.encryptor().update(texto)

    # 2. MAC sobre o criptograma (encrypt-then-MAC)
    h = hmac.HMAC(chave_hmac, hashes.SHA256())
    h.update(nonce + criptograma)
    tag = h.finalize()

    # Guardar salt + nonce + criptograma + tag
    with open(fich + '.enc', 'wb') as f:
        f.write(salt + nonce + criptograma + tag)
    print(f"Ficheiro cifrado: {fich}.enc")

def dec(fich):
    password = getpass.getpass("Password: ")

    with open(fich, 'rb') as f:
        dados = f.read()

    # Separar componentes
    salt        = dados[:16]
    nonce       = dados[16:32]
    tag         = dados[-32:]        # últimos 32 bytes = tag HMAC
    criptograma = dados[32:-32]      # meio = criptograma

    # Derivar duas chaves
    chave_aes, chave_hmac = derivar_chaves(password, salt)

    # 1. Verificar MAC ANTES de decifrar!
    h = hmac.HMAC(chave_hmac, hashes.SHA256())
    h.update(nonce + criptograma)
    try:
        h.verify(tag)
    except Exception:
        print("ERRO: MAC inválido — ficheiro adulterado!")
        sys.exit(1)

    # 2. Só decifra se MAC for válido
    cipher = Cipher(algorithms.AES(chave_aes), modes.CTR(nonce))
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
