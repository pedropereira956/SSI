from multiprocessing import Process, Pipe
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Parâmetros públicos fixos
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

pn = dh.DHParameterNumbers(p, g)
parametros = pn.parameters()

def derivar_chave(K):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'dh_aes_gcm'
    )
    return hkdf.derive(K)

def alice_process(conn):
    # Gerar chaves
    chave_privada = parametros.generate_private_key()
    chave_publica = chave_privada.public_key()

    # 1. Alice → Bob
    conn.send(chave_publica.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    # 2. Bob → Alice
    chave_publica_bob = load_pem_public_key(conn.recv())

    # 3. Calcular K e derivar chave AES
    K = chave_privada.exchange(chave_publica_bob)
    chave_aes = derivar_chave(K)

    # Cifrar mensagem com AES-GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(chave_aes)
    mensagem = b"Ola Bob! Esta mensagem e secreta!"
    criptograma = aesgcm.encrypt(nonce, mensagem, None)

    # Enviar nonce + criptograma
    conn.send(nonce + criptograma)
    print(f"Alice enviou: {mensagem.decode()}")

def bob_process(conn):
    # Gerar chaves
    chave_privada = parametros.generate_private_key()
    chave_publica = chave_privada.public_key()

    # 1. Alice → Bob
    chave_publica_alice = load_pem_public_key(conn.recv())

    # 2. Bob → Alice
    conn.send(chave_publica.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    # 3. Calcular K e derivar chave AES
    K = chave_privada.exchange(chave_publica_alice)
    chave_aes = derivar_chave(K)

    # Receber e decifrar mensagem
    dados = conn.recv()
    nonce = dados[:12]
    criptograma = dados[12:]
    aesgcm = AESGCM(chave_aes)
    mensagem = aesgcm.decrypt(nonce, criptograma, None)
    print(f"Bob recebeu:  {mensagem.decode()}")

if __name__ == '__main__':
    parent_conn, child_conn = Pipe()
    p1 = Process(target=alice_process, args=(parent_conn,))
    p2 = Process(target=bob_process, args=(child_conn,))
    p1.start(); p2.start()
    p1.join(); p2.join()
