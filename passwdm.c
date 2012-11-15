#include <stdio.h>

#define LINE_BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
	// Create a buffer to store input in.
	char line_buffer[LINE_BUFFER_SIZE];

	// Receive input from standard input.
	while(1) {
		printf("> ");
		// If fgets returns NULL, it means there was an error, or an EOF was received.
		if(fgets(line_buffer, 1024, stdin) == NULL)
			break;
	}

	printf("\n");
	return 0;
}
