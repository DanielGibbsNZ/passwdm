CFLAGS = -Wall -Wextra -Werror
LIBS = -lreadline
TARGET = passwdm

all: $(TARGET)

$(TARGET): passwdm.o polarssl/aes.o polarssl/sha2.o
	$(CC) $(LIBS) passwdm.o polarssl/aes.o polarssl/sha2.o -o $(TARGET)

passwdm.o: passwdm.c
polarssl/aes.o: polarssl/aes.c polarssl/aes.h
polarssl/sha2.o: polarssl/sha2.c polarssl/sha2.h

.PHONY: clean
clean:
	rm -f *.o passwdm
