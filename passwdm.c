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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "polarssl/sha2.h"
#include "polarssl/aes.h"

#define COMMAND_DELIMETERS " \t\r\n"
#define DEFAULT_PROMPT "> "

#define DATABASE_SIGNATURE 0x5057444d

#define KEY_SIZE 32
#define IV_SIZE 16

struct database_header {
	uint32_t signature;
	uint32_t signature2;
	uint32_t signature3;
	uint32_t signature4;
};

struct database {
	char *name;
	int fd;
	unsigned char key[KEY_SIZE];
	struct database_header *header;
};

void perform_command(char *);
void create_database(char *);
void open_database(char *);
void close_database();
void save_database();

char *db_dir = NULL;
char *prompt = DEFAULT_PROMPT;

struct database *db = NULL;

int main() {
	// Check that password database directory exists, and if not creates it.
	char *home_dir = getenv("HOME");
	if(home_dir == NULL) {
		fprintf(stderr, "Unable to locate home directory.");
		return 1;
	}
	if(asprintf(&db_dir, "%s/.passwdm", home_dir) == -1) {
		fprintf(stderr, "Out of memory.\n");
		return 1;
	}
	if(mkdir(db_dir, S_IRUSR | S_IWUSR | S_IXUSR) == -1 && errno != EEXIST) {
		fprintf(stderr, "Unable to create password database directory.\n");
		return 1;
	}

	// Prevent TAB from auto-completing file names.
	rl_bind_key('\t', rl_insert);

	// Read commands from the user.
	char *command;
	while(1) {
		command = readline(prompt);
		if(command == NULL) {
			if(db != NULL) {
				printf("close\n");
				close_database();
				continue;
			}
			else {
				printf("exit\n");
				break;
			}
		}

		// Maintain a history of commands.
		if(*command)
			add_history(command);

		// Catch exit commands.
		if(strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0)
			break;
		// Handle commands.
		else
			perform_command(command);

		free(command);
	}

	close_database();

	return 0;
}

void perform_command(char *command) {
	char *keyword = strtok(command, COMMAND_DELIMETERS);
	if(keyword == NULL)
		return;
	// Create a password database.
	else if(strcmp(keyword, "create") == 0) {
		// Get the database name.
		char *db_name = strtok(NULL, COMMAND_DELIMETERS);
		char *arg = strtok(NULL, COMMAND_DELIMETERS);
		if(arg != NULL) {
			printf("Unknown argument: %s\n", arg);
		}
		else if(db_name == NULL) {
			printf("Password database name required.\n");
		}
		else if(db != NULL) {
			printf("Current password database must be closed before another one can be created.\n");
		}
		// Change to the database and update the prompt.
		else {
			create_database(db_name);
		}
	}
	// Open a password database.
	else if(strcmp(keyword, "open") == 0) {
		// Get the database name.
		char *db_name = strtok(NULL, COMMAND_DELIMETERS);
		char *arg = strtok(NULL, COMMAND_DELIMETERS);
		if(arg != NULL) {
			printf("Unknown argument: %s\n", arg);
		}
		else if(db_name == NULL) {
			printf("Password database name required.\n");
		}
		else if(db != NULL) {
			printf("Current password database must be closed before another one can be opened.\n");
		}
		// Change to the database and update the prompt.
		else {
			open_database(db_name);
		}
	}
	// Close the current password database.
	else if(strcmp(keyword, "close") == 0) {
		char *arg = strtok(NULL, COMMAND_DELIMETERS);
		if(db == NULL) {
			printf("No password database currently open.\n");
		}
		else if(arg != NULL && strcmp(arg, db->name) != 0) {
			printf("Unknown argument: %s\n", arg);
		}
		else {
			close_database();
		}
	}
	else {
		printf("%s: command not found.\n", keyword);
	}
}

void create_database(char *db_name) {
	// Get passphrase for this database.
	char *pass_prompt;
	if(asprintf(&pass_prompt, "Passphrase for %s: ", db_name) == -1) {
		printf("Out of memory.\n");
		return;
	}
	char *passphrase = getpass(pass_prompt);
	char *db_filename;
	if(asprintf(&db_filename, "%s/%s", db_dir, db_name) == -1) {
		printf("Out of memory.\n");
		return;
	}
	int db_fd = open(db_filename, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if(db_fd == -1) {
		if(errno == EEXIST) {
			printf("%s: password database already exists.\n", db_name);
			return;
		}
		else {
			printf("%s: error creating password database.\n", db_name);
			return;
		}
	}
	struct database *d = (struct database *)malloc(sizeof(struct database));
	if(d == NULL) {
		printf("Out of memory.\n");
		close(db_fd);
		return;
	}
	d->name = strdup(db_name);
	if(d->name == NULL) {
		printf("Out of memory.\n");
		close(db_fd);
		return;
	}
	// Generate the key.
	sha2((unsigned char *)passphrase, strlen(passphrase), d->key, 0);
	// Zero the password.
	memset(passphrase, 0, strlen(passphrase));
	d->fd = db_fd;
	d->header = (struct database_header *)malloc(sizeof(struct database_header));
	if(d->header == NULL) {
		printf("Out of memory.\n");
		close(db_fd);
		return;
	}
	d->header->signature = DATABASE_SIGNATURE;
	if(asprintf(&prompt, "%s> ", db_name) == -1) {
		printf("Out of memory.\n");
		prompt = DEFAULT_PROMPT;
		close(db_fd);
		return;
	}
	db = d;
}

void open_database(char *db_name) {
	char *db_filename;
	if(asprintf(&db_filename, "%s/%s", db_dir, db_name) == -1) {
		printf("Out of memory.\n");
		return;
	}
	int db_fd = open(db_filename, O_RDWR);
	if(db_fd == -1) {
		printf("%s: password database not found.\n", db_name);
		return;
	}
	// Get passphrase for this database.
	char *pass_prompt;
	if(asprintf(&pass_prompt, "Passphrase for %s: ", db_name) == -1) {
		printf("Out of memory.\n");
		close(db_fd);
		return;
	}
	char *passphrase = getpass(pass_prompt);
	// Validate passphrase.
	struct database *d = (struct database *)malloc(sizeof(struct database));
	if(d == NULL) {
		printf("Out of memory.\n");
		close(db_fd);
		return;
	}
	d->name = strdup(db_name);
	if(d->name == NULL) {
		printf("Out of memory.\n");
		close(db_fd);
		return;
	}
	d->fd = db_fd;
	d->header = (struct database_header *)malloc(sizeof(struct database_header));
	if(d->header == NULL) {
		printf("Out of memory.\n");
		close(db_fd);
		return;
	}
	// Read IV first.
	unsigned char iv[IV_SIZE];
	if(read(db_fd, iv, IV_SIZE) < IV_SIZE) {
		printf("Invalid database file.\n");
		close(db_fd);
		return;
	}

	// Create key.
	sha2((unsigned char *)passphrase, strlen(passphrase), d->key, 0);
	// Zero the password.
	memset(passphrase, 0, strlen(passphrase));

	// Read encrypted data.
	if(read(db_fd, d->header, sizeof(struct database_header)) < (int)sizeof(struct database_header)) {
		printf("Invalid database file.\n");
		close(db_fd);
		return;
	}

	// Decrypt.
	aes_context ctx;
	if(aes_setkey_dec(&ctx, d->key, KEY_SIZE * 8) != 0) {
		printf("Error loading database.\n");
		close(db_fd);
		return;
	}
	if(aes_crypt_cbc(&ctx, AES_DECRYPT, sizeof(struct database_header), iv, (unsigned char *)d->header, (unsigned char *)d->header) != 0 ) {
		printf("Error loading database.\n");
		close(db_fd);
		return;
	}

	if(d->header->signature != DATABASE_SIGNATURE) {
		printf("Invalid passphrase.\n");
		close(db_fd);
		return;
	}
	if(asprintf(&prompt, "%s> ", db_name) == -1) {
		printf("Out of memory.\n");
		prompt = DEFAULT_PROMPT;
		close(db_fd);
		return;
	}
	db = d;
}

void close_database() {
	if(db != NULL) {
		save_database();
		close(db->fd);
	}
	prompt = DEFAULT_PROMPT;
	db = NULL;
}

void save_database() {
	// Start writing at the beginning of the file.
	if(lseek(db->fd, 0, SEEK_SET) == -1) {
		printf("Error saving database.\n");
		close(db->fd);
		return;
	}

	// Prepare data to be written.
	ssize_t n = (ssize_t)sizeof(struct database_header);
	unsigned char *encrypted = (unsigned char *)malloc(n);
	if(encrypted == NULL) {
		printf("Out of memory.\n");
		close(db->fd);
		return;
	}

	// Preapre IV.
	unsigned char iv[IV_SIZE], iv_updated[IV_SIZE];
	memcpy(iv, "1234567890123456", IV_SIZE);
	memcpy(iv_updated, iv, IV_SIZE);

	// Encrypt.
	aes_context ctx;
	if(aes_setkey_enc(&ctx, db->key, KEY_SIZE * 8) != 0) {
		printf("Error saving database.\n");
		close(db->fd);
		free(encrypted);
		return;
	}
	if(aes_crypt_cbc(&ctx, AES_ENCRYPT, n, iv_updated, (unsigned char *)db->header, encrypted) != 0) {
		printf("Error saving database.\n");
		close(db->fd);
		free(encrypted);
		return;
	}

	// Write IV first.
	if(write(db->fd, iv, IV_SIZE) < IV_SIZE) {
		printf("Error saving database.\n");
		close(db->fd);
		free(encrypted);
		return;
	}

	// Write encrypted data.
	if(write(db->fd, encrypted, n) < n) {
		printf("Error saving database.\n");
		close(db->fd);
		free(encrypted);
		return;
	}

	close(db->fd);
	free(encrypted);
}
