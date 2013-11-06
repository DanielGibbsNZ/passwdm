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
#include "polarssl/sha2.h"
#include "polarssl/aes.h"

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

#define COMMAND_DELIMETERS " \t\r\n"
#define DEFAULT_PROMPT "> "

static void perform_command(char *);
static void save_and_close();

static char *db_dir = NULL;
static char *prompt = DEFAULT_PROMPT;
static struct database *db = NULL;

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
				save_and_close();
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

	save_and_close();
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
			char *db_filename;
			if(asprintf(&db_filename, "%s/%s", db_dir, db_name) == -1) {
				printf("Out of memory.\n");
				return;
			}
			if(asprintf(&prompt, "%s> ", db_name) == -1) {
				printf("Out of memory.\n");
				prompt = DEFAULT_PROMPT;
				return;
			}
			char *pass_prompt;
			if(asprintf(&pass_prompt, "Passphrase for %s: ", db_name) == -1) {
				printf("Out of memory.\n");
				return;
			}
			char *passphrase = getpass(pass_prompt);
			if(create_database(&db, db_filename, passphrase) != 0) {
				printf("Error creating database.\n");
				prompt = DEFAULT_PROMPT;
				return;
			}
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
			char *db_filename;
			if(asprintf(&db_filename, "%s/%s", db_dir, db_name) == -1) {
				printf("Out of memory.\n");
				return;
			}
			if(asprintf(&prompt, "%s> ", db_name) == -1) {
				printf("Out of memory.\n");
				prompt = DEFAULT_PROMPT;
				return;
			}
			char *pass_prompt;
			if(asprintf(&pass_prompt, "Passphrase for %s: ", db_name) == -1) {
				printf("Out of memory.\n");
				return;
			}
			char *passphrase = getpass(pass_prompt);
			if(open_database(&db, db_filename, passphrase) != 0) {
				printf("Error opening database.\n");
				prompt = DEFAULT_PROMPT;
				return;
			}
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
			save_and_close();
		}
	}
	else {
		printf("%s: command not found.\n", keyword);
	}
}

void save_and_close() {
	if(db == NULL)
		return;
	if(save_database(db) != 0) {
		printf("Error saving database.\n");
	}
	close_database(db);
	prompt = DEFAULT_PROMPT;
	db = NULL;
}
