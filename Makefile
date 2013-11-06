CFLAGS = -Wall -Wextra -Werror -D_GNU_SOURCE
LIBS = -lreadline
TARGET = passwdm

all: $(TARGET)

$(TARGET): passwdm.o database.o polarssl/aes.o polarssl/sha256.o
	$(CC) $(LIBS) passwdm.o database.o polarssl/aes.o polarssl/sha256.o -o $(TARGET)

passwdm.o: passwdm.c
database.o: database.c database.h
polarssl/aes.o: polarssl/aes.c polarssl/aes.h
polarssl/sha2.o: polarssl/sha256.c polarssl/sha256.h

.PHONY: clean
clean:
	rm -f *.o passwdm
