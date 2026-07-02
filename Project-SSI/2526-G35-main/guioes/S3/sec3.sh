# Exercício 1
cat > leitor.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <ficheiro>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "r");
    if (f == NULL) {
        perror("Erro ao abrir ficheiro");
        return 1;
    }

    char linha[256];
    while (fgets(linha, sizeof(linha), f)) {
        printf("%s", linha);
    }

    fclose(f);
    return 0;
}
EOF

# Compilar
gcc leitor.c -o leitor
ls -l leitor
# Exercício 2
sudo adduser userssi --disabled-password --gecos ""
sudo passwd userssi
# Exercício 3
sudo chown userssi leitor
sudo chown userssi braga.txt
ls -l leitor braga.txt
# Exercício 4
./leitor braga.txt
# Exercício 5
sudo chmod u+s leitor
ls -l leitor
# Exercício 6
./leitor braga.txt
# Resultado: "Braga é a cidade dos arcades"
# Com setuid ativo, o processo passa a correr com o utilizador
# efetivo userssi (dono do executável) em vez de ubuntu.
# Como userssi é o dono do braga.txt (r--------), consegue lê-lo.
# O setuid é útil mas perigoso — se mal usado pode permitir
# escalonamento de privilégios indesejado.
