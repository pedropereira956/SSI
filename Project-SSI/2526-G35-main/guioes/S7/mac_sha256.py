import sys
import os
import hashlib

def setup(fkey):
    chave = os.urandom(32)  # 32 bytes = 256 bits para SHA256
    with open(fkey, 'wb') as f:
        f.write(chave)
    print(f"Chave gerada em: {fkey}")

def mac(fich, fkey):
    # Ler chave e mensagem
    with open(fkey, 'rb') as f:
        chave = f.read()
    with open(fich, 'rb') as f:
        mensagem = f.read()

    # prefix-MAC: H(k || m)
    tag = hashlib.sha256(chave + mensagem).digest()

    # Guardar tag
    with open(fich + '.mac', 'wb') as f:
        f.write(tag)
    print(f"MAC guardado em: {fich}.mac")

def ver(fich, fkey):
    # Ler chave e mensagem
    with open(fkey, 'rb') as f:
        chave = f.read()
    with open(fich, 'rb') as f:
        mensagem = f.read()

    # Ler tag original
    with open(fich + '.mac', 'rb') as f:
        tag_original = f.read()

    # Recalcular e comparar
    tag_calculada = hashlib.sha256(chave + mensagem).digest()
    resultado = tag_calculada == tag_original
    print(resultado)

# Ler argumentos
operacao = sys.argv[1]

if operacao == "setup":
    setup(sys.argv[2])
elif operacao == "mac":
    mac(sys.argv[2], sys.argv[3])
elif operacao == "ver":
    ver(sys.argv[2], sys.argv[3])
