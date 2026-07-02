import sys

def preproc(s):
    l = []
    for c in s:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def cesar_dec(texto, k):
    resultado = []
    for c in texto:
        pos = ord(c) - ord('A')
        nova_pos = (pos - k) % 26
        resultado.append(chr(nova_pos + ord('A')))
    return "".join(resultado)

# Ler argumentos
criptograma = preproc(sys.argv[1])
palavras    = [p.upper() for p in sys.argv[2:]]

# Força bruta — tentar todas as 26 chaves
for k in range(26):
    tentativa = cesar_dec(criptograma, k)
    for palavra in palavras:
        if palavra in tentativa:
            chave = chr(k + ord('A'))
            print(chave)
            print(tentativa)
            sys.exit()

