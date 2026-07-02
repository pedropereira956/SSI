import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def gerar_chaves_rsa(nome_utilizador, password=None):
    """
    Gera um par de chaves RSA e guarda em ficheiros PEM.
    Se password for fornecida, a chave privada fica protegida por AES-256-CBC.
    """
    print(f"  A gerar chaves RSA para '{nome_utilizador}'...")

    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    chave_publica = chave_privada.public_key()

    os.makedirs("chaves_privadas", exist_ok=True)
    os.makedirs("chaves_publicas", exist_ok=True)

    # Proteger chave privada com password se fornecida
    if password:
        if isinstance(password, str):
            password = password.encode('utf-8')
        algoritmo_cifra = serialization.BestAvailableEncryption(password)
        print(f"  [🔐] Chave privada protegida com password.")
    else:
        algoritmo_cifra = serialization.NoEncryption()

    pem_privada = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=algoritmo_cifra
    )
    with open(f"chaves_privadas/{nome_utilizador}_privada.pem", "wb") as f:
        f.write(pem_privada)

    pem_publica = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"chaves_publicas/{nome_utilizador}_publica.pem", "wb") as f:
        f.write(pem_publica)

    print(f"  [✓] '{nome_utilizador}' criado com sucesso!")


if __name__ == "__main__":
    import getpass
    print("--- GERADOR DE IDENTIDADES (RSA 2048-bit) ---\n")
    print("Podes proteger as chaves privadas com uma password.")
    print("Deixa em branco para não usar password (menos seguro).\n")

    usar_password = input("Usar password para proteger chaves privadas? (s/n): ").strip().lower()

    utilizadores = ["alice", "bob", "joao", "pedro"]
    for utilizador in utilizadores:
        chave_path = f"chaves_privadas/{utilizador}_privada.pem"
        if os.path.exists(chave_path):
            print(f"  [→] '{utilizador}' já existe — a saltar.")
        else:
            pw = None
            if usar_password == 's':
                pw = getpass.getpass(f"  Password para '{utilizador}': ")
                if not pw:
                    print(f"  [!] Password vazia — chave criada SEM proteção.")
                    pw = None
            gerar_chaves_rsa(utilizador, password=pw)

    print("\n[✓] Concluído!")
    print("    Pastas: 'chaves_privadas/' e 'chaves_publicas/'")
    print("    NOTA: O servidor gera a sua própria identidade ao arrancar.")
    if usar_password == 's':
        print("    IMPORTANTE: Guarda bem as passwords — sem elas não consegues ligar!")