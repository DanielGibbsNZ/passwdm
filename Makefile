passwdm: passwdm.c
	gcc passwdm.c polarssl/*.c -o passwdm -lreadline -Wall -Wextra
