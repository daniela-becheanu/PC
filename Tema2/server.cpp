#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "helpers.h" 
#include <netinet/tcp.h>
#include <bits/stdc++.h>
#include <iostream>
using namespace std;

void usage(char *file)
{
	fprintf(stderr, "Usage: %s server_port\n", file);
	exit(0);
}

int main(int argc, char **argv)
{
	char buffer[BUFLEN];
	struct sockaddr_in cli_addr;
	int n, i;
	socklen_t clilen;

	/* key = id */
	map<string, struct client> clients;
	map<string, map<string, client>> topics;
	map<string, queue<tcp_msg>> messages;
	map<string, struct client>::iterator it;
	map<string, map<string, client>>::iterator it_topics;
	fd_set read_fds, tmp_fds;
	struct sockaddr_in serv_addr;
	int fdmax, new_tcp_sock;
	char sub[20], topic[50];
	uint8_t SF;
	struct client cli;


	int flag = 1;
	int portno = atoi(argv[1]);

	if (argc < 2) {
		usage(argv[0]);
	}

	DIE(portno == 0, "atoi");

	int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
	DIE(tcp_sock < 0, "socket");

	portno = atoi(argv[1]);
	DIE(portno == 0, "atoi");

	/*Setare struct sockaddr_in pentru a asculta pe portul respectiv */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(portno);
	serv_addr.sin_addr.s_addr = INADDR_ANY;

	/*Deschidere socket*/
	int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
	DIE(udp_sock == -1, "socket failed");
	
	/* Legare proprietati de socket */
	int b = bind(udp_sock,
         	(struct sockaddr*) &serv_addr, 
         	sizeof(serv_addr));
	DIE(b == -1, "binding UDP failed");

	n = setsockopt(tcp_sock, SOL_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
	DIE(n < 0, "disabling Nagle's algorithm failed");

	b = bind(tcp_sock, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr));
	DIE(b < 0, "binding TCP failed");

	n = listen(tcp_sock, MAX_CLIENTS);
	DIE(n < 0, "listen");

	FD_ZERO(&read_fds);
	FD_ZERO(&tmp_fds);

	FD_SET(STDIN_FILENO, &read_fds);
	FD_SET(tcp_sock, &read_fds);
	FD_SET(udp_sock, &read_fds);
	fdmax = udp_sock;

	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	while (1) {
		tmp_fds = read_fds; 
		
		n = select(fdmax + 1, &tmp_fds, NULL, NULL, NULL);
		DIE(n < 0, "select failed");

		if (FD_ISSET(STDIN_FILENO, &tmp_fds)) {
			memset(buffer, 0, sizeof(buffer));
			fgets(buffer, BUFLEN - 1, stdin);

			if (strncmp(buffer, "exit", strlen("exit")) == 0) {
				for (it = clients.begin(); it != clients.end(); ++it) {

					if (it->second.connected == true) {
						//n = send(it->second.sock, buffer, strlen(buffer), 0);
						//DIE(n < 0, "send");
						close(it->second.sock);
					}
    		    }
				break;
			}
		}

		for (i = 1; i <= fdmax; i++) {
			if (FD_ISSET(i, &tmp_fds)) {
				if (i == udp_sock) {
					struct udp_msg *msg = (struct udp_msg*)malloc(sizeof(udp_msg));
					struct tcp_msg *tcpmsg = (struct tcp_msg*)malloc(sizeof(tcp_msg));
					memset(buffer, 0, sizeof(buffer));
					int r = recvfrom(i, buffer, BUFLEN, 0,
							(struct sockaddr*) &cli_addr,
							&clilen);
					DIE(r < 0, "recvfrom");
					memset(tcpmsg, 0, sizeof(tcp_msg));
					memcpy(&tcpmsg->udpmsg, buffer, sizeof(udp_msg));
					memcpy(&tcpmsg->cli_addr, &cli_addr, sizeof(sockaddr_in));

					if (topics.find(tcpmsg->udpmsg.topic) == topics.end()) {
						map<string, client> new_map;
						topics.insert({tcpmsg->udpmsg.topic, new_map});
						continue;
					}

					for (it = topics[tcpmsg->udpmsg.topic].begin(); it != topics[tcpmsg->udpmsg.topic].end(); ++it) {
						if (it->second.connected == true) {
							n = send(it->second.sock, tcpmsg, sizeof(tcp_msg), 0);
							DIE(n < 0, "send");
							continue;
						}

						if (it->second.SF == 1) {
							messages[it->first].push(*tcpmsg);
						}
					}
				} else if (i == tcp_sock) {
					// daca cheia era deja
					
					clilen = sizeof(cli_addr);
					new_tcp_sock = accept(tcp_sock, (struct sockaddr *) &cli_addr, &clilen);
					DIE(new_tcp_sock < 0, "accept new TCP failed");
					flag = 1;
					n = setsockopt(new_tcp_sock, SOL_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
					
					
					memset(buffer, 0, sizeof(buffer));
					n = recv(new_tcp_sock, buffer, sizeof(buffer), 0);
					DIE(n < 0, "recv TCP failed");

					if (clients.find(buffer) != clients.end()) {
						it = clients.find(buffer);
						if (it->second.connected == true) {
							printf("Client %s already connected.\n", buffer);
							close(new_tcp_sock);
							continue;
						}
						
						FD_CLR(it->second.sock, &read_fds); // nu cred ca mai trb
						// close(it->second.sock);
						it->second.sock = new_tcp_sock;
						it->second.connected = true;
						FD_SET(new_tcp_sock, &read_fds);
						if (new_tcp_sock > fdmax) { 
							fdmax = new_tcp_sock;
						}

						printf("New client %s connected from %s:%d.\n", buffer,
							inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

						for (it_topics = topics.begin(); it_topics != topics.end(); ++it_topics) {
							if (it_topics->second.find(it->first) != it_topics->second.end()) {
								it_topics->second[it->first].connected = true;
							}
						}

						while (!messages[it->first].empty()) {
							tcp_msg tcpmsg = messages[it->first].front();
							n = send(it->second.sock, &tcpmsg, sizeof(tcp_msg), 0);
							DIE(n < 0, "send");
							messages[it->first].pop();
						}
						continue;					
					}

					cli.sock = new_tcp_sock;
					cli.connected = true;
					clients.insert({buffer, cli});

					FD_SET(new_tcp_sock, &read_fds);

					if (new_tcp_sock > fdmax) { 
						fdmax = new_tcp_sock;
					}

					queue<tcp_msg> new_q;
					messages.insert({buffer, new_q});

					printf("New client %s connected from %s:%d.\n", buffer,
						inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

					
				} else {

					memset(buffer, 0, BUFLEN);
					n = recv(i, buffer, BUFLEN, 0);
					DIE(n < 0, "recv");

					if (n == 0) {
						//conexiunea s-a inchis
						for (it = clients.begin(); it != clients.end(); it++) {
							if (it->second.sock == i) {
								printf("Client %s disconnected.\n", it->first.c_str());
								it->second.connected = false;
								close(i);
								FD_CLR(i, &read_fds);
								for (it_topics = topics.begin(); it_topics != topics.end(); ++it_topics) {
									if (it_topics->second.find(it->first) != it_topics->second.end()) {
										// printf("%s %d\n", it->first.c_str(), it_topics->second[it->first].connected);
										it_topics->second[it->first].connected = false;
										// printf("%s %d\n", it->first.c_str(), it_topics->second[it->first].connected);
									}
								}
								break;
							}
						}
						// se scoate din multimea de citire socketul inchis 
					} else { // se primeste un anunt de (un)subscribe la un topic
										
						if (!strncmp(buffer, "subscribe", strlen("subscribe"))) {
							sscanf(buffer, "%s %s %hhd", sub, topic, &SF);
							// daca topicul exista deja in hashmap, trebuie updatat map ul coresp lui
							if (topics.find(topic) != topics.end()) {
								for (it = clients.begin(); it != clients.end(); ++it) {
									if (it->second.sock == i) {
										it->second.SF = SF;
										topics[topic].insert({it->first, it->second});
										break;
									}
								}
							} else {
								// printf("nu exista\n");
								for (it = clients.begin(); it != clients.end(); ++it) {
									if (it->second.sock == i) {
										map<string, client> new_map;
										it->second.SF = SF;
										new_map.insert({it->first, it->second});
										topics.insert({topic, new_map});
										break;
									}
								}
							}
						} else if (!strncmp(buffer, "unsubscribe", strlen("unsubscribe"))) {
							if (topics.find(topic) != topics.end()) {
								for (it = clients.begin(); it != clients.end(); ++it) {
									if (it->second.sock == i) {
										topics[topic].erase(it);
										break;
									}
								}
							} else {
								map<string, client> new_map;
								topics.insert({topic, new_map});
							}
						}
					}
				}
			}
		}
	}

	// close_all_sockets(fdmax, tmp_fds);
	close(tcp_sock);
	close(udp_sock);
	return 0;
}
