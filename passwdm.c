#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <readline/readline.h>
#include <readline/history.h>

#define COMMAND_DELIMETERS " \t\r\n"

void perform_command(char *);
void create_database(char *);
void open_database(char *);
void close_database();

char *db_dir = NULL;

char *database = NULL;
char *prompt = "> ";
FILE *db_file = NULL;

int main(int argc, char *argv[]) {
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
			if(database != NULL) {
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
		else if(database != NULL) {
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
		else if(database != NULL) {
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
		if(arg != NULL && strcmp(arg, database) != 0) {
			printf("Unknown argument: %s\n", arg);
		}
		else if(database == NULL) {
			printf("No password database currently open.\n");
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
	FILE *db = fdopen(db_fd, "w");
	if(db == NULL) {
		printf("%s: error creating password database.\n", db_name);
		return;
	}
	database = strdup(db_name);
	if(asprintf(&prompt, "%s> ", database) == -1) {
		printf("Out of memory.\n");
		fclose(db);
		return;
	}
	db_file = db;
}

void open_database(char *db_name) {
	char *db_filename;
	if(asprintf(&db_filename, "%s/%s", db_dir, db_name) == -1) {
		printf("Out of memory.\n");
		return;
	}
	FILE *db = fopen(db_filename, "rb");
	if(db == NULL) {
		printf("%s: password database not found.\n", db_name);
		return;
	}
	// Get passphrase for this database.
	char *pass_prompt;
	if(asprintf(&pass_prompt, "Passphrase for %s: ", db_name) == -1) {
		printf("Out of memory.\n");
		fclose(db);
		return;
	}
	char *passphrase = getpass(pass_prompt);
	// Validate passphrase.
	if(passphrase) {
		database = strdup(db_name);
		if(asprintf(&prompt, "%s> ", database) == -1) {
			printf("Out of memory.\n");
			fclose(db);
			return;
		}
		db_file = db;
	}
	else {
		printf("Invalid passphrase.\n");
		fclose(db);
	}
}

void close_database() {
	if(db_file != NULL)
		fclose(db_file);
	prompt = "> ";
	database = NULL;
}
