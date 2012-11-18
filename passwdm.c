#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>

#define COMMAND_DELIMETERS " \t\r\n"

void perform_command(char *);

char *database = NULL;
char *prompt = "> ";

int main(int argc, char *argv[]) {
	// Prevent TAB from auto-completing file names.
	rl_bind_key('\t', rl_insert);

	// Read commands from the user.
	char *command;
	while((command = readline(prompt)) != NULL) {
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

	// If EOF was received, output a new line.
	if(command == NULL)
		printf("\n");

	return 0;
}

void perform_command(char *command) {
	char *keyword = strtok(command, COMMAND_DELIMETERS);
	if(keyword == NULL)
		return;
	// Open a password database.
	else if(strcmp(keyword, "open") == 0) {
		// Get the database name.
		char *dbname = strtok(NULL, COMMAND_DELIMETERS);
		char *arg = strtok(NULL, COMMAND_DELIMETERS);
		if(arg != NULL) {
			printf("Unknown argument: %s\n", arg);
		}
		else if(dbname == NULL) {
			printf("Password database name required.\n");
		}
		else if(database != NULL) {
			printf("Current password database must be closed before another one can be opened.\n");
		}
		// Change to the database and update the prompt.
		else {
			// Get passphrase for this database.
			char *pass_prompt;
			asprintf(&pass_prompt, "Passphrase for %s: ", dbname);
			char *passphrase = getpass(pass_prompt);
			// Validate passphrase.
			if(passphrase) {
				database = strdup(dbname);
				asprintf(&prompt, "%s> ", database);
			}
			else {
				printf("Invalid passphrase.\n");
			}
		}
	}
	// Close the current password database.
	else if(strcmp(keyword, "close") == 0) {
		char *arg = strtok(NULL, COMMAND_DELIMETERS);
		if(arg != NULL) {
			printf("Unknown argument: %s\n", arg);
		}
		else if(database == NULL) {
			printf("No password database currently open.\n");
		}
		else {
			database = NULL;
			prompt = "> ";
		}
	}
	else {
		printf("%s: command not found\n", keyword);
	}
}
