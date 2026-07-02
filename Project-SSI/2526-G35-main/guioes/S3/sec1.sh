#!/bin/bash
# Exercício 1
echo "Lisboa é a capital de Portugal" > lisboa.txt
echo "Porto é a cidade Invicta" > porto.txt
echo "Braga é a cidade dos arcades" > braga.txt
# Exercício 2
ls -l lisboa.txt
# Exercício 3
chmod 666 lisboa.txt
# Exercício 4
chmod 500 porto.txt
ls -l porto.txt
# Exercício 5
chmod 400 braga.txt
ls -l braga.txt
# Exercício 6
mkdir dir1 dir2
ls -ld dir1 dir2
# Exercício 7
chmod 700 dir2
ls -ld dir2
