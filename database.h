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

#ifndef DATABASE_H
#define DATABASE_H

#include <stdint.h>

#define DATABASE_KEY_SIZE 32

struct database_header {
	uint32_t signature;
	uint32_t signature2;
	uint32_t signature3;
	uint32_t signature4;
};

struct database {
	char *name;
	int fd;
	unsigned char key[DATABASE_KEY_SIZE];
	struct database_header *header;
};

int create_database(struct database **, char *, char *);
int open_database(struct database **, char *, char *);
int save_database(struct database *);
void close_database(struct database *);

void database_perror(char *);

#endif
