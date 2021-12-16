#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
extern "C" {
#include "helpers.h"
}
#include <bits/stdc++.h>

void decode_message(struct sockaddr_in cli_addr, udp_msg *recv, char *sent) {
	float num;
	double double_num;
	uint8_t power;
	switch (recv->data_type) {
		case 0:
			// printf("e int\n");

			if (recv->content[0]) { // poate merge cu %d
				sprintf(sent, "%s:%d - %s - INT - -%u\n", inet_ntoa(cli_addr.sin_addr), 
					ntohs(cli_addr.sin_port), recv->topic, ntohl(*(uint32_t *)(recv->content + 1)));
			} else {
				sprintf(sent, "%s:%d - %s - INT - %u\n", inet_ntoa(cli_addr.sin_addr), 
					ntohs(cli_addr.sin_port), recv->topic, ntohl(*(uint32_t *)(recv->content + 1)));
			}
			// printf("sent = %s\n", sent);
			break;

		case 1:
			double_num = ntohs(*((uint16_t *)(recv->content)));
			sprintf(sent, "%s:%d - %s - SHORT_REAL - %.2f\n", inet_ntoa(cli_addr.sin_addr), 
					ntohs(cli_addr.sin_port), recv->topic, double_num/ 100);
			break;
		
		case 2:
			num = ntohl(*((uint32_t *)(recv->content + 1)));
			power = *((uint8_t *)(recv->content + 5));

			if (recv->content[0]) { //e neg
				sprintf(sent, "%s:%d - %s - FLOAT - -%.8g\n", inet_ntoa(cli_addr.sin_addr), 
					ntohs(cli_addr.sin_port), recv->topic, num / pow(10, power));
			} else {
				sprintf(sent, "%s:%d - %s - FLOAT - %.8g\n", inet_ntoa(cli_addr.sin_addr), 
					ntohs(cli_addr.sin_port), recv->topic, num / pow(10, power));				
			}
			break;
		default:
			sprintf(sent, "%s:%d - %s - STRING - %s\n", inet_ntoa(cli_addr.sin_addr), 
					ntohs(cli_addr.sin_port), recv->topic, recv->content);
			break;

	}
}

void usage(char *file)
{
	fprintf(stderr, "Usage: %s server_address server_port\n", file);
	exit(0);
}

int main(int argc, char **argv)
{
	int sockfd, n, ret;
	struct sockaddr_in serv_addr;
	char buffer[BUFLEN];

	if (argc < 4) {
		usage(argv[0]);
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	DIE(sockfd < 0, "socket");

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(atoi(argv[3]));
	ret = inet_aton(argv[2], &serv_addr.sin_addr);
	DIE(ret == 0, "inet_aton");

	ret = connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
	DIE(ret < 0, "connect");

	ret = send(sockfd, argv[1], strlen(argv[1]), 0);
	DIE(ret < 0, "Could not send ID");

	fd_set read_fds, tmp_fds;
	FD_ZERO(&read_fds);
	FD_ZERO(&tmp_fds);

	FD_SET(sockfd, &read_fds);
	FD_SET(STDIN_FILENO, &read_fds);
	int fdmax = sockfd;

	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	while (1) {
		tmp_fds = read_fds; 

		ret = select(fdmax + 1, &tmp_fds, NULL, NULL, NULL);
		DIE(ret < 0, "select");
		
		int ok = 0;
		for (int i = 0; i <= fdmax; i++) {
			if (FD_ISSET(i, &tmp_fds)) {
				if (i == sockfd) {
					struct tcp_msg *tcpmsg = (struct tcp_msg*)malloc(sizeof(tcp_msg));
					memset(tcpmsg, 0, sizeof(tcp_msg));
					n = recv(i, tcpmsg, sizeof(tcp_msg), 0);
					DIE(n < 0, "recv");
					if (n == 0) {
						goto end;
					}

					// struct udp_msg *msg = (struct udp_msg*)malloc(sizeof(udp_msg));
					
					// memcpy(tcpmsg, buffer, sizeof(tcp_msg));
					memset(buffer, 0, sizeof(buffer));
					decode_message(tcpmsg->cli_addr, &tcpmsg->udpmsg, buffer);

					printf("%s", buffer);
				} else if (i == STDIN_FILENO) {
					
					// se citeste de la tastatura
					memset(buffer, 0, BUFLEN);
					fgets(buffer, BUFLEN - 1, stdin);
					
					if (!strncmp(buffer, "exit", strlen("exit"))) {
						goto end;
					}

					n = send(sockfd, buffer, sizeof(buffer), 0);
					DIE(n < 0, "send");
					if (!strncmp(buffer, "subscribe", strlen("subscribe"))) {
						printf("Subscribed to topic.\n");
					} else if (!strncmp(buffer, "unsubscribe", strlen("unsubscribe"))) {
						printf("Unsubscribed from topic.\n");
					}

				}
			}
		}
	}

end:
	close(sockfd);

	return 0;
}
