import sys

def preproc(s):
    l = []
    for c in s:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def vigenere_dec(texto, chave):
    resultado = []
    for i, c in enumerate(texto):
        k = ord(chave[i % len(chave)]) - ord('A')
        pos = ord(c) - ord('A')
        nova_pos = (pos - k) % 26
        resultado.append(chr(nova_pos + ord('A')))
    return "".join(resultado)

# Ler argumentos
tam_chave   = int(sys.argv[1])
criptograma = preproc(sys.argv[2])
palavras    = [p.upper() for p in sys.argv[3:]]

# Letras mais frequentes em Português
freq_pt = "AEOSIMNRUT"

# Atacar cada fatia independentemente
chave = []
for i in range(tam_chave):
    # Extrair a fatia i
    fatia = criptograma[i::tam_chave]
    
    # Contar frequências na fatia
    contagem = {}
    for c in fatia:
        contagem[c] = contagem.get(c, 0) + 1
    
    # Ordenar por frequência
    ordenado = sorted(contagem, key=lambda c: contagem[c], reverse=True)
    
    # Tentar as letras mais frequentes como candidatas ao 'A'
    melhor_k = ord(ordenado[0]) - ord('A')
    chave.append(melhor_k)

# Construir chave e decifrar
chave_str = "".join(chr(k + ord('A')) for k in chave)
tentativa = vigenere_dec(criptograma, chave_str)

# Verificar se alguma palavra está no texto
for palavra in palavras:
    if palavra in tentativa:
        print(chave_str)
        print(tentativa)
        sys.exit()

# Se não encontrou com análise de frequência, força bruta nas fatias
from itertools import product
for combinacao in product(range(26), repeat=tam_chave):
    chave_str = "".join(chr(k + ord('A')) for k in combinacao)
    tentativa = vigenere_dec(criptograma, chave_str)
    for palavra in palavras:
        if palavra in tentativa:
            print(chave_str)
            print(tentativa)
            sys.exit()
