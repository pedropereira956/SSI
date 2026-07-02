import sys
import hashpumpy

def ataque(fich, ext):
    # Ler mensagem original
    with open(fich, 'rb') as f:
        mensagem = f.read()

    # Ler MAC original (em hex para o hashpumpy)
    with open(fich + '.mac', 'rb') as f:
        tag_bytes = f.read()
    tag_hex = tag_bytes.hex()

    # Realizar o ataque — chave tem 32 bytes
    novo_mac_hex, msg_estendida = hashpumpy.hashpump(
        tag_hex,          # MAC original
        mensagem,         # mensagem original
        ext.encode(),     # extensão a adicionar
        32                # tamanho da chave (bytes)
    )

    # Guardar mensagem estendida e novo MAC
    with open(fich + '.ext', 'wb') as f:
        f.write(msg_estendida)
    with open(fich + '.ext.mac', 'wb') as f:
        f.write(bytes.fromhex(novo_mac_hex))

    print(f"Mensagem estendida guardada em: {fich}.ext")
    print(f"Novo MAC guardado em: {fich}.ext.mac")

# Ler argumentos
ataque(sys.argv[1], sys.argv[2])
