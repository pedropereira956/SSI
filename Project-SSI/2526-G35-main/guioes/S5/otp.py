import sys
import os

def setup(n, ficheiro_chave):
    chave = os.urandom(n)
    with open(ficheiro_chave, 'wb') as f:
        f.write(chave)

def enc(ficheiro_msg, ficheiro_chave):
    with open(ficheiro_msg, 'rb') as f:
        mensagem = f.read()
    with open(ficheiro_chave, 'rb') as f:
        chave = f.read()
    criptograma = bytes(a ^ b for a, b in zip(mensagem, chave))
    with open(ficheiro_msg + '.enc', 'wb') as f:
        f.write(criptograma)

def dec(ficheiro_enc, ficheiro_chave):
    with open(ficheiro_enc, 'rb') as f:
        criptograma = f.read()
    with open(ficheiro_chave, 'rb') as f:
        chave = f.read()
    mensagem = bytes(a ^ b for a, b in zip(criptograma, chave))
    with open(ficheiro_enc + '.dec', 'wb') as f:
        f.write(mensagem)

# Ler argumentos
operacao = sys.argv[1]

if operacao == "setup":
    setup(int(sys.argv[2]), sys.argv[3])
elif operacao == "enc":
    enc(sys.argv[2], sys.argv[3])
elif operacao == "dec":
    dec(sys.argv[2], sys.argv[3])
