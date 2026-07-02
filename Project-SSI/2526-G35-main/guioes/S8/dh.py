from multiprocessing import Process, Pipe
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key
)

# Parâmetros públicos fixos (p, g) fornecidos na ficha
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

# Criar parâmetros DH
pn = dh.DHParameterNumbers(p, g)
parametros = pn.parameters()

def alice_process(conn):
    # Gerar chaves de Alice
    chave_privada = parametros.generate_private_key()
    chave_publica = chave_privada.public_key()

    # 1. Alice → Bob: enviar chave pública
    alice_bytes = chave_publica.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(alice_bytes)

    # 2. Bob → Alice: receber chave pública de Bob
    bob_bytes = conn.recv()
    chave_publica_bob = load_pem_public_key(bob_bytes)

    # 3. Calcular segredo partilhado K
    K = chave_privada.exchange(chave_publica_bob)
    print(f"Alice K: {K.hex()}")

def bob_process(conn):
    # Gerar chaves de Bob
    chave_privada = parametros.generate_private_key()
    chave_publica = chave_privada.public_key()

    # 1. Alice → Bob: receber chave pública de Alice
    alice_bytes = conn.recv()
    chave_publica_alice = load_pem_public_key(alice_bytes)

    # 2. Bob → Alice: enviar chave pública
    bob_bytes = chave_publica.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(bob_bytes)

    # 3. Calcular segredo partilhado K
    K = chave_privada.exchange(chave_publica_alice)
    print(f"Bob   K: {K.hex()}")

if __name__ == '__main__':
    parent_conn, child_conn = Pipe()
    p1 = Process(target=alice_process, args=(parent_conn,))
    p2 = Process(target=bob_process, args=(child_conn,))
    p1.start(); p2.start()
    p1.join(); p2.join()
