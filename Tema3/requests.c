#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"


/* Functie care creeaza un mesaj de tip GET request */
char *compute_get_request(char *host, char *url, char *cookies, char *token)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    sprintf(line, "GET %s HTTP/1.1", url);
    compute_message(message, line);

    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    if (cookies) {
        sprintf(line, "Cookie: %s", cookies);
        compute_message(message, line); 
    }

    if (token) {
        sprintf(line, "Authorization: Bearer %s", token);
        compute_message(message, line);
    }

    compute_message(message, "");
    return message;
}

/* Functie care creeaza un mesaj de tip POST request */
char *compute_post_request(char *host, char *url, char* content_type,
    char *body_data, char *cookies, char *token)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);
    
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    sprintf(line, "Content-Type: %s", content_type);
    compute_message(message, line);

    sprintf(line, "Content-Length: %ld", strlen(body_data));
    compute_message(message, line);

    if (cookies) {
        sprintf(line, "Cookies: %s", cookies);
        compute_message(message, line); 
    }

    if (token) {
        sprintf(line, "Authorization: Bearer %s", token);
        compute_message(message, line);
    }

    compute_message(message, "");

    compute_message(message, body_data);

    free(line);
    return message;
}

/* Functie care creeaza un mesaj de tip DELETE request */
char *compute_delete_request(char *host, char *url, char *token)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    sprintf(line, "DELETE %s HTTP/1.1", url);
    compute_message(message, line);

    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    if (token) {
        sprintf(line, "Authorization: Bearer %s", token);
        compute_message(message, line); 
    }

    compute_message(message, "");
    return message;
}