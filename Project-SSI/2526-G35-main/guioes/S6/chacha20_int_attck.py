import sys

def ataque(fctxt, pos, ptxt_pos, new_ptxt_pos):
    # Converter strings para bytes
    ptxt_bytes     = ptxt_pos.encode()
    new_ptxt_bytes = new_ptxt_pos.encode()

    # Ler criptograma (com NONCE nos primeiros 16 bytes)
    with open(fctxt, 'rb') as f:
        dados = f.read()

    nonce       = dados[:16]
    criptograma = bytearray(dados[16:])  # bytearray para permitir modificações

    # Aplicar o ataque byte a byte na posição indicada
    for i in range(len(ptxt_bytes)):
        criptograma[pos + i] ^= ptxt_bytes[i] ^ new_ptxt_bytes[i]

    # Guardar criptograma manipulado
    with open(fctxt + '.attck', 'wb') as f:
        f.write(nonce + bytes(criptograma))
    print(f"Criptograma manipulado guardado em: {fctxt}.attck")

# Ler argumentos
ataque(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4])
