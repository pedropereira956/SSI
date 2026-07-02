#!/bin/bash

# Exercício 1
getfacl porto.txt
# Exercício 2
sudo setfacl -m g:grupo-ssi:w porto.txt
# Exercício 3
getfacl porto.txt
# Diferenças face ao Exercício 1:
# - Foi adicionada uma linha "group:grupo-ssi:-w-" com permissão
#   de escrita específica para o grupo grupo-ssi
# - Apareceu uma linha "mask::--w-" que define a permissão máxima
#   que qualquer ACL estendida pode ter neste ficheiro
# - O "+" no ls -l indica que o ficheiro tem ACLs estendidas ativas
# Exercício 4
su - alice
echo "Texto adicionado por alice" >> /home/ubuntu/porto.txt
cat /home/ubuntu/porto.txt
# Resultado:
# - O echo >> funcionou porque alice pertence ao grupo-ssi
#   que tem permissão de escrita (w) via ACL estendida.
# - O cat deu Permission denied porque a ACL apenas concedeu
#   permissão de escrita (w) ao grupo-ssi, sem permissão de leitura (r).
# - Isto demonstra a granularidade das ACLs: é possível dar escrita
#   sem leitura a um grupo específico, algo impossível com as
#   permissões tradicionais Unix.
