import sys

def preproc(s):
    l = []
    for c in s:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def cesar_enc(texto, k):
    resultado = []
    for c in texto:
        pos = ord(c) - ord('A')        # posição da letra (0-25)
        nova_pos = (pos + k) % 26      # deslocar k posições
        resultado.append(chr(nova_pos + ord('A')))  # converter de volta
    return "".join(resultado)

def cesar_dec(texto, k):
    return cesar_enc(texto, -k)        # decifrar é o inverso!

# Ler argumentos
operacao = sys.argv[1]
chave    = sys.argv[2].upper()
mensagem = preproc(sys.argv[3])

# Converter chave para número
k = ord(chave) - ord('A')

# Executar operação
if operacao == "enc":
    print(cesar_enc(mensagem, k))
elif operacao == "dec":
    print(cesar_dec(mensagem, k))
