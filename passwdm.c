#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>

#define COMMAND_DELIMETERS " \t\r\n"

void perform_command(char *);

int main(int argc, char *argv[]) {
	// Prevent TAB from auto-completing file names.
	rl_bind_key('\t', rl_insert);

	// Read commands from the user.
	char *command;
	while((command = readline("> ")) != NULL) {
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
	else {
		printf("%s: command not found\n", keyword);
	}
}
