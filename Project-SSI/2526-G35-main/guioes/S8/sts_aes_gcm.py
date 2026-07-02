from multiprocessing import Process, Pipe
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key,
    load_pem_private_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
import os

# Parâmetros DH
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
pn = dh.DHParameterNumbers(p, g)
parametros = pn.parameters()

def mkpair(x, y):
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

def derivar_chave(K):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'sts_aes_gcm'
    ).derive(K)

def assinar(chave_privada, *msgs):
    # Concatenar todas as mensagens e assinar
    dados = b''.join(msgs)
    return chave_privada.sign(
        dados,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verificar(chave_publica, assinatura, *msgs):
    dados = b''.join(msgs)
    chave_publica.verify(
        assinatura,
        dados,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def validar_certificado(cert_bytes, ca_cert):
    cert = x509.load_pem_x509_certificate(cert_bytes)
    # Verificar assinatura do certificado com chave pública da CA
    ca_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm
    )
    return cert

def alice_process(conn):
    # Carregar chave privada e certificados
    with open('Alice.key', 'rb') as f:
        chave_privada = load_pem_private_key(f.read(), password=None)
    with open('Alice.crt', 'rb') as f:
        alice_cert_bytes = f.read()
    with open('CA.crt', 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Gerar chaves DH
    dh_privada = parametros.generate_private_key()
    dh_publica = dh_privada.public_key()
    gx = dh_publica.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    # 1. Alice → Bob: gˣ
    conn.send(gx)

    # 2. Bob → Alice: gʸ + SigB(gʸ,gˣ) + CertB
    dados = conn.recv()
    gy, resto = unpair(dados)
    sig_bob, cert_bob_bytes = unpair(resto)

    # Validar certificado de Bob com CA
    cert_bob = validar_certificado(cert_bob_bytes, ca_cert)
    print("Alice: certificado de Bob validado ✅")

    # Verificar assinatura de Bob
    verificar(cert_bob.public_key(), sig_bob, gy, gx)
    print("Alice: assinatura de Bob verificada ✅")

    # 3. Alice → Bob: SigA(gˣ,gʸ) + CertA
    sig_alice = assinar(chave_privada, gx, gy)
    conn.send(mkpair(sig_alice, alice_cert_bytes))

    # 4. Calcular K
    chave_publica_bob = load_pem_public_key(gy)
    K = dh_privada.exchange(chave_publica_bob)
    chave_aes = derivar_chave(K)

    # Cifrar e enviar mensagem
    nonce = os.urandom(12)
    aesgcm = AESGCM(chave_aes)
    mensagem = b"Ola Bob autenticado!"
    criptograma = aesgcm.encrypt(nonce, mensagem, None)
    conn.send(nonce + criptograma)
    print(f"Alice enviou: {mensagem.decode()}")

def bob_process(conn):
    # Carregar chave privada e certificados
    with open('Bob.key', 'rb') as f:
        chave_privada = load_pem_private_key(f.read(), password=None)
    with open('Bob.crt', 'rb') as f:
        bob_cert_bytes = f.read()
    with open('CA.crt', 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Gerar chaves DH
    dh_privada = parametros.generate_private_key()
    dh_publica = dh_privada.public_key()
    gy = dh_publica.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    # 1. Alice → Bob: receber gˣ
    gx = conn.recv()

    # 2. Bob → Alice: gʸ + SigB(gʸ,gˣ) + CertB
    sig_bob = assinar(chave_privada, gy, gx)
    conn.send(mkpair(gy, mkpair(sig_bob, bob_cert_bytes)))

    # 3. Alice → Bob: SigA(gˣ,gʸ) + CertA
    dados = conn.recv()
    sig_alice, cert_alice_bytes = unpair(dados)

    # Validar certificado de Alice com CA
    cert_alice = validar_certificado(cert_alice_bytes, ca_cert)
    print("Bob: certificado de Alice validado ✅")

    # Verificar assinatura de Alice
    verificar(cert_alice.public_key(), sig_alice, gx, gy)
    print("Bob: assinatura de Alice verificada ✅")

    # 4. Calcular K
    chave_publica_alice = load_pem_public_key(gx)
    K = dh_privada.exchange(chave_publica_alice)
    chave_aes = derivar_chave(K)

    # Receber e decifrar mensagem
    dados = conn.recv()
    nonce = dados[:12]
    criptograma = dados[12:]
    aesgcm = AESGCM(chave_aes)
    mensagem = aesgcm.decrypt(nonce, criptograma, None)
    print(f"Bob recebeu: {mensagem.decode()}")

if __name__ == '__main__':
    parent_conn, child_conn = Pipe()
    p1 = Process(target=alice_process, args=(parent_conn,))
    p2 = Process(target=bob_process, args=(child_conn,))
    p1.start(); p2.start()
    p1.join(); p2.join()
