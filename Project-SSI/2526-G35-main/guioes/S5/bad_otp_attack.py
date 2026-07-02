import sys
import random

# Ler argumentos
tam_chave    = int(sys.argv[1])
ficheiro_enc = sys.argv[2]
palavras     = [p.lower() for p in sys.argv[3:]]

# Ler criptograma
with open(ficheiro_enc, 'rb') as f:
    criptograma = f.read()

# Tentar todas as 65536 sementes possíveis (2 bytes)
for i in range(2**16):
    # Replicar exatamente o bad_prng: semente são 2 bytes
    semente = i.to_bytes(2, byteorder='big')
    random.seed(semente)
    chave = random.randbytes(tam_chave)
    
    tentativa = bytes(a ^ b for a, b in zip(criptograma, chave))
    
    try:
        texto = tentativa.decode('utf-8')
        for palavra in palavras:
            if palavra in texto.lower():
                print(texto, end='')
                sys.exit()
    except:
        continue

