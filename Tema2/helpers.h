#ifndef _HELPERS_H
#define _HELPERS_H 1

#include <stdio.h>
#include <stdlib.h>

/*
 * Macro de verificare a erorilor
 * Exemplu:
 *     int fd = open(file_name, O_RDONLY);
 *     DIE(fd == -1, "open failed");
 */

struct client {
	bool connected;
	int sock;
	int SF;
};

struct udp_msg{
	char topic[50];
	uint8_t data_type;
	char content[1500];
};

struct tcp_msg {
	struct sockaddr_in cli_addr;
	struct udp_msg udpmsg;
};

#define DIE(assertion, call_description)	\
	do {									\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",	\
					__FILE__, __LINE__);	\
			perror(call_description);		\
			exit(EXIT_FAILURE);				\
		}									\
	} while(0)

#define BUFLEN		1600  // dimensiunea maxima a calupului de date
#define MAX_CLIENTS	10    // numarul maxim de clienti in asteptare

#endif
