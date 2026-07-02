import sys

def preproc(s):
    l = []
    for c in s:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def vigenere_enc(texto, chave):
    resultado = []
    for i, c in enumerate(texto):
        k = ord(chave[i % len(chave)]) - ord('A')  # chave roda!
        pos = ord(c) - ord('A')
        nova_pos = (pos + k) % 26
        resultado.append(chr(nova_pos + ord('A')))
    return "".join(resultado)

def vigenere_dec(texto, chave):
    resultado = []
    for i, c in enumerate(texto):
        k = ord(chave[i % len(chave)]) - ord('A')  # chave roda!
        pos = ord(c) - ord('A')
        nova_pos = (pos - k) % 26
        resultado.append(chr(nova_pos + ord('A')))
    return "".join(resultado)

# Ler argumentos
operacao = sys.argv[1]
chave    = preproc(sys.argv[2])
mensagem = preproc(sys.argv[3])

if operacao == "enc":
    print(vigenere_enc(mensagem, chave))
elif operacao == "dec":
    print(vigenere_dec(mensagem, chave))
