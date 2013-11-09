/*
 *   Passwdm: CLI-based password manager.
 *   Copyright (C) 2012  Daniel Gibbs
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "database.h"

#include "polarssl/aes.h"
#include "polarssl/sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DATABASE_SIGNATURE 0x5057444d
#define IV_SIZE 16

#define DATABASE_ERROR_SYS -1
#define DATABASE_ERROR_OK 0
#define DATABASE_ERROR_IO 1
#define DATABASE_ERROR_KEY 2
#define DATABASE_ERROR_ENCRYPT 3
#define DATABASE_ERROR_DECRYPT 4
#define DATABASE_ERROR_PASSPHRASE 5

static int database_errno = 0;

static char *database_strerror(int error) {
	switch(error) {
		case DATABASE_ERROR_SYS: return strerror(errno);
		case DATABASE_ERROR_OK: return "Success";
		case DATABASE_ERROR_IO: return "I/O error";
		case DATABASE_ERROR_KEY: return "Invalid key";
		case DATABASE_ERROR_ENCRYPT: return "Encryption failed";
		case DATABASE_ERROR_DECRYPT: return "Decryption failed";
		case DATABASE_ERROR_PASSPHRASE: return "Incorrect passphrase";
		default: return "Unknown error";
	}
}

int create_database(struct database **database, char *filename, char *passphrase) {
	// Open the database file.
	int fd;
	if((fd = open(filename, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)) == -1) {
		database_errno = DATABASE_ERROR_SYS;
		return -1;
	}

	// Setup the database structure.
	struct database *d = (struct database *)calloc(1, sizeof(struct database));
	if(!d) {
		errno = ENOMEM;
		database_errno = DATABASE_ERROR_SYS;
		close(fd);
		return -1;
	}
	d->fd = fd;
	d->name = strdup(filename);
	if(!d->name) {
		errno = ENOMEM;
		database_errno = DATABASE_ERROR_SYS;
		free(d);
		close(fd);
		return -1;
	}
	d->header = (struct database_header *)malloc(sizeof(struct database_header));
	if(!d->header) {
		errno = ENOMEM;
		database_errno = DATABASE_ERROR_SYS;
		free(d->name);
		free(d);
		close(fd);
		return -1;
	}
	d->header->signature = DATABASE_SIGNATURE;

	// Generate the key.
	sha256((unsigned char *)passphrase, strlen(passphrase), d->key, 0);

	// Zero the password.
	memset(passphrase, 0, strlen(passphrase));

	// Success.
	*database = d;
	return 0;
}

int open_database(struct database **database, char *filename, char *passphrase) {
	// Open the database file.
	int fd;
	if((fd = open(filename, O_RDWR)) == -1) {
		database_errno = -1;
		return -1;
	}

#define fail() 	free(d->name); \
				free(d->header); \
				free(d); \
				close(fd); \
				return -1;

	// Setup the database structure.
	struct database *d = (struct database *)calloc(1, sizeof(struct database));
	if(!d) {
		errno = ENOMEM;
		database_errno = DATABASE_ERROR_SYS;
		fail();
	}
	d->fd = fd;
	d->name = strdup(filename);
	if(!d->name) {
		errno = ENOMEM;
		database_errno = DATABASE_ERROR_SYS;
		fail();
	}
	d->header = (struct database_header *)calloc(1, sizeof(struct database_header));
	if(!d->header) {
		errno = ENOMEM;
		database_errno = DATABASE_ERROR_SYS;
		fail();
	}

	// Generate the key.
	sha256((unsigned char *)passphrase, strlen(passphrase), d->key, 0);

	// Zero the passphrase.
	memset(passphrase, 0, strlen(passphrase));

	// Read IV first.
	unsigned char iv[IV_SIZE];
	if(read(fd, iv, IV_SIZE) < IV_SIZE) {
		database_errno = DATABASE_ERROR_IO;
		fail();
	}

	// Read encrypted data.
	if(read(fd, d->header, sizeof(*d->header)) < (signed)sizeof(sizeof(*d->header))) {
		database_errno = DATABASE_ERROR_IO;
		fail();
	}

	// Decrypt the data.
	aes_context ctx;
	if(aes_setkey_dec(&ctx, d->key, DATABASE_KEY_SIZE * 8) != 0) {
		database_errno = DATABASE_ERROR_KEY;
		fail();
	}
	if(aes_crypt_cbc(&ctx, AES_DECRYPT, sizeof(*d->header), iv, (unsigned char *)d->header, (unsigned char *)d->header) != 0) {
		database_errno = DATABASE_ERROR_DECRYPT;
		fail();
	}

	// Validate the database.
	if(d->header->signature != DATABASE_SIGNATURE) {
		database_errno = DATABASE_ERROR_PASSPHRASE;
		fail();
	}

	// Success.
	*database = d;
	return 0;

#undef fail
}

int save_database(struct database *database) {
	// Start writing at the beginning of the file.
	if(lseek(database->fd, 0, SEEK_SET) != 0) {
		database_errno = DATABASE_ERROR_SYS;
		return -1;
	}

	// Prepare data to be written.
	ssize_t n = (ssize_t)sizeof(*database->header);
	unsigned char *encrypted = (unsigned char *)calloc(n, sizeof(unsigned char));
	if(!encrypted) {
		errno = ENOMEM;
		database_errno = DATABASE_ERROR_SYS;
		return -1;
	}

	// Prepare IV.
	unsigned char iv[IV_SIZE], iv_updated[IV_SIZE];
	memcpy(iv, "1234567890123456", IV_SIZE);
	memcpy(iv_updated, iv, IV_SIZE);

	// Encrypt.
	aes_context ctx;
	if(aes_setkey_enc(&ctx, database->key, DATABASE_KEY_SIZE * 8) != 0) {
		database_errno = DATABASE_ERROR_KEY;
		free(encrypted);
		return -1;
	}
	if(aes_crypt_cbc(&ctx, AES_ENCRYPT, n, iv_updated, (unsigned char *)database->header, encrypted) != 0) {
		database_errno = DATABASE_ERROR_ENCRYPT;
		free(encrypted);
		return -1;
	}

	// Write IV first.
	if(write(database->fd, iv, IV_SIZE) < IV_SIZE) {
		database_errno = DATABASE_ERROR_IO;
		free(encrypted);
		return -1;
	}

	// Write encrypted data.
	if(write(database->fd, encrypted, n) < n) {
		database_errno = DATABASE_ERROR_IO;
		free(encrypted);
		return -1;
	}

	free(encrypted);
	return 0;
}

void close_database(struct database *database) {
	if(!database)
		return;
	close(database->fd);
	free(database->name);
	free(database->header);
	free(database);
}

void database_perror(char *s) {
	if(s == NULL)
		fprintf(stderr, "%s\n", database_strerror(database_errno));
	else
		fprintf(stderr, "%s: %s\n", s, database_strerror(database_errno));
}
