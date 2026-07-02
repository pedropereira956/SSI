import sys
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import getpass

def derivar_chave(password, salt):
    # AES-GCM só precisa de 1 chave — 32 bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000
    )
    return kdf.derive(password.encode())

def enc(fich):
    password = getpass.getpass("Password: ")

    with open(fich, 'rb') as f:
        texto = f.read()

    # Gerar salt e nonce
    salt  = os.urandom(16)
    nonce = os.urandom(12)   # AES-GCM usa nonce de 12 bytes!

    # Derivar chave
    chave = derivar_chave(password, salt)

    # Cifrar + autenticar numa só operação!
    aesgcm = AESGCM(chave)
    criptograma = aesgcm.encrypt(nonce, texto, None)
    # criptograma já inclui a tag automaticamente!

    # Guardar salt + nonce + criptograma(+tag)
    with open(fich + '.enc', 'wb') as f:
        f.write(salt + nonce + criptograma)
    print(f"Ficheiro cifrado: {fich}.enc")

def dec(fich):
    password = getpass.getpass("Password: ")

    with open(fich, 'rb') as f:
        dados = f.read()

    # Separar componentes
    salt        = dados[:16]
    nonce       = dados[16:28]   # 12 bytes de nonce
    criptograma = dados[28:]     # criptograma + tag

    # Derivar chave
    chave = derivar_chave(password, salt)

    # Decifrar + verificar integridade numa só operação!
    aesgcm = AESGCM(chave)
    try:
        texto = aesgcm.decrypt(nonce, criptograma, None)
    except Exception:
        print("ERRO: autenticação falhou — ficheiro adulterado!")
        sys.exit(1)

    with open(fich + '.dec', 'wb') as f:
        f.write(texto)
    print(f"Ficheiro decifrado: {fich}.dec")

# Ler argumentos
operacao = sys.argv[1]

if operacao == "enc":
    enc(sys.argv[2])
elif operacao == "dec":
    dec(sys.argv[2])
