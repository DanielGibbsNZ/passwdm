CC = clang

passwdm: passwdm.c
	$(CC) passwdm.c polarssl/*.c -o passwdm -lreadline -Wall -Wextra
