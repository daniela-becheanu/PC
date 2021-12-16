#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include <stdbool.h>
#include "parson.h"

/* Functie care verifica daca un sir de caractere este un numar */
bool check_number(char *s) {
    if (!strcmp("\n", s)) {
        return false;
    }

    for (int i = 0; i < strlen(s) - 1; ++i) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
    }

    /* Se sterge ultimul caracter, care este newline */
    s[strlen(s) - 1] = '\0';
    return true;
}

/* Functie care citeste input-ul de la tastatura pana la primirea unuia
 * valid */
void check_validity(char *type, char *buff) {
    printf("%s=", type);
    memset(buff, 0, BUFLEN);
    fgets(buff, BUFLEN - 1, stdin);

    if (!strcmp("id", type) || !strcmp("page_count", type)) {
        while (!check_number(buff)) {
            printf("Insert %s again\n", type);
            printf("%s=", type);
            memset(buff, 0, BUFLEN);
            fgets(buff, BUFLEN - 1, stdin);
        }
        return;
    }

    while (!strcmp("\n", buff)) {
        printf("Insert %s again\n", type);
        printf("%s=", type);
        memset(buff, 0, BUFLEN);
        fgets(buff, BUFLEN - 1, stdin);
    }

    /* Se sterge ultimul caracter, care este newline */
    buff[strlen(buff) - 1] = '\0';
}

int main(int argc, char *argv[])
{
    char *message;
    char *response;
    int sockfd;
    char buffer[BUFLEN], buff_user[BUFLEN], buff_pass[BUFLEN],
        buff_title[BUFLEN], buff_author[BUFLEN], buff_genre[BUFLEN],
        buff_publisher[BUFLEN], buff_page_count[BUFLEN], buff_id[BUFLEN];

    char *path = calloc(BUFLEN, sizeof(char));
    char *cookie;
    char *token;

    while (1) {
        memset(buffer, 0, BUFLEN);
        fgets(buffer, BUFLEN - 1, stdin);

        /* Conditie de oprire */
        if (!strcmp("exit\n", buffer)) {
            break;
        }
        
        if (!strcmp("register\n", buffer)) {
            check_validity("username", buff_user);
            check_validity("password", buff_pass);

            /* Se creeaza obiectul JSON cu username si password si string-ul
             * corespunzator acestuia */
            JSON_Value *root_value = json_value_init_object();
            JSON_Object *root_object = json_value_get_object(root_value);
            
            json_object_set_string(root_object, "username", buff_user);
            json_object_set_string(root_object, "password", buff_pass);
        
            char *msg_sent = json_serialize_to_string_pretty(root_value);
            
            sockfd = open_connection("34.118.48.238", 8080, AF_INET,
                SOCK_STREAM, 0);

            if (sockfd < 0)  {
                error("error open connection!");
            }
            
            /* Se creeaza POST request-ul */
            message = compute_post_request("34.118.48.238",
                "/api/v1/tema/auth/register", "application/json", msg_sent,
                NULL, NULL);
            
            /* Se trimite mesajul, se primeste raspunsul si raspunsul se
             * afiseaza la tastatura */
            send_to_server(sockfd, message);
            response = receive_from_server(sockfd);
            puts(response);

            /* Se elibereaza memoria pentru response si message si se inchide
             * conexiunea */
            free(response);
            free(message);
            json_free_serialized_string(msg_sent);
            json_value_free(root_value);
            close_connection(sockfd);
            continue;
        }

        if (!strcmp("login\n", buffer)) {
            check_validity("username", buff_user);
            check_validity("password", buff_pass);

            /* Se creeaza obiectul JSON cu username si password si string-ul
             * corespunzator acestuia */
            JSON_Value *root_value = json_value_init_object();
            JSON_Object *root_object = json_value_get_object(root_value);
            
            json_object_set_string(root_object, "username", buff_user);
            json_object_set_string(root_object, "password", buff_pass);
        
            char *msg_sent = json_serialize_to_string_pretty(root_value);

            sockfd = open_connection("34.118.48.238", 8080, AF_INET,
                SOCK_STREAM, 0);

            if (sockfd < 0)  {
                error("error open connection!");
            }
            
            /* Se creeaza POST request-ul */
            message = compute_post_request("34.118.48.238",
                "/api/v1/tema/auth/login", "application/json", msg_sent,
                NULL, NULL);

            /* Se trimite mesajul, se primeste raspunsul si raspunsul se
             * afiseaza la tastatura */
            send_to_server(sockfd, message);
            response = receive_from_server(sockfd);
            puts(response);
            
            /* Se extrage cookie-ul si se salveaza intr-o variabila (daca
             * operatiunea de login se efectueaza cu succes, atunci ar trebui
             * sa se gaseasca cookie-ul) */
            cookie = strstr(response, "Set-Cookie: ");
            if (cookie) {
                cookie = cookie + strlen("Set-Cookie: ");
                strtok(cookie, ";");
            }

            /* Se elibereaza memoria pentru response, message, obiectul JSON
             * si string-ul asociat acestuia si se inchide conexiunea */
            free(response);
            free(message);
            json_free_serialized_string(msg_sent);
            json_value_free(root_value);
            close_connection(sockfd);
            continue;
        }

        if (!strcmp("get_books\n", buffer)) {
            sockfd = open_connection("34.118.48.238", 8080, AF_INET,
                SOCK_STREAM, 0);

            if (sockfd < 0)  {
                error("error open connection!");
            }
            
            /* Se creeaza GET request-ul */
            message = compute_get_request("34.118.48.238",
                "/api/v1/tema/library/books", NULL, token);

            /* Se trimite mesajul, se primeste raspunsul si raspunsul se
             * afiseaza la tastatura */
            send_to_server(sockfd, message);
            response = receive_from_server(sockfd);
            puts(response);

            /* Se elibereaza memoria pentru response si message si se inchide
             * conexiunea */
            free(response);
            free(message);
            close_connection(sockfd);
            continue;
        }

        if (!strcmp("enter_library\n", buffer)) {
            sockfd = open_connection("34.118.48.238", 8080, AF_INET,
                SOCK_STREAM, 0);

            if (sockfd < 0)  {
                error("error open connection!");
            }
            
            /* Se creeaza GET request-ul */
            message = compute_get_request("34.118.48.238",
                "/api/v1/tema/library/access", cookie, NULL);

            /* Se trimite mesajul, se primeste raspunsul si raspunsul se
             * afiseaza la tastatura */
            send_to_server(sockfd, message);
            response = receive_from_server(sockfd);
            puts(response);

            /* Se extrage token-ul si se salveaza intr-o variabila (daca
             * operatiunea de enter_library se efectueaza cu succes, atunci ar
             * trebui sa se gaseasca token-ul) */
            token = strstr(response, "\"token\":\"");
            if (token) {
                token = token + strlen("\"token\":\"");
                strtok(token, "\"");
            }
            
            /* Se elibereaza memoria pentru response si message si se inchide
             * conexiunea */
            free(response);
            free(message);
            close_connection(sockfd);
            continue;
        }

        if (!strcmp("get_book\n", buffer)) {
            check_validity("id", buff_id);

            sockfd = open_connection("34.118.48.238", 8080, AF_INET,
                SOCK_STREAM, 0);

            if (sockfd < 0)  {
                error("error open connection!");
            }

            /* Se creeaza GET request-ul */
            strcpy(path, "/api/v1/tema/library/books/");
            strcat(path, buff_id);
            message = compute_get_request("34.118.48.238",  path, cookie, token);

            /* Se trimite mesajul, se primeste raspunsul si raspunsul se
             * afiseaza la tastatura */
            send_to_server(sockfd, message);
            response = receive_from_server(sockfd);
            puts(response);

            /* Se elibereaza memoria pentru response si message si se inchide
             * conexiunea */
            free(response);
            free(message);
            close_connection(sockfd);
            continue;
        }

        if (!strcmp("add_book\n", buffer)) {
            check_validity("title", buff_title);
            check_validity("author", buff_author);
            check_validity("genre", buff_genre);
            check_validity("publisher", buff_publisher);
            check_validity("page_count", buff_page_count);
            
            /* Se creeaza obiectul JSON cu title, author, genre, page_count si
             * publisher si string-ul corespunzator acestuia */
            JSON_Value *root_value = json_value_init_object();
            JSON_Object *root_object = json_value_get_object(root_value);
            
            json_object_set_string(root_object, "title", buff_title);
            json_object_set_string(root_object, "author", buff_author);
            json_object_set_string(root_object, "genre", buff_genre);
            json_object_set_number(root_object, "page_count",
                atoi(buff_page_count));
            json_object_set_string(root_object, "publisher", buff_publisher);
        
            char *msg_sent = json_serialize_to_string_pretty(root_value);

            sockfd = open_connection("34.118.48.238", 8080, AF_INET,
                SOCK_STREAM, 0);

            if (sockfd < 0)  {
                error("error open connection!");
            }
            
            /* Se creeaza POST request-ul */
            message = compute_post_request("34.118.48.238",
                "/api/v1/tema/library/books", "application/json",
	            msg_sent, cookie, token);

            /* Se trimite mesajul, se primeste raspunsul si raspunsul se
             * afiseaza la tastatura */
            send_to_server(sockfd, message);
            response = receive_from_server(sockfd);
            puts(response);

            /* Se elibereaza memoria pentru response, message, obiectul JSON
             * si string-ul asociat acestuia si se inchide conexiunea */
            free(response);
            free(message);
            json_free_serialized_string(msg_sent);
            json_value_free(root_value);
            close_connection(sockfd);
            continue;
        }

        if (!strcmp("delete_book\n", buffer)) {
            check_validity("id", buff_id);

            sockfd = open_connection("34.118.48.238", 8080, AF_INET,
                SOCK_STREAM, 0);

            if (sockfd < 0)  {
                error("error open connection!");
            }

            /* Se creeaza DELETE request-ul */
            strcpy(path, "/api/v1/tema/library/books/");
            strcat(path, buff_id);
            message = compute_delete_request("34.118.48.238", path, token);

            /* Se trimite mesajul, se primeste raspunsul si raspunsul se
             * afiseaza la tastatura */
            send_to_server(sockfd, message);
            response = receive_from_server(sockfd);
            puts(response);

            /* Se elibereaza memoria pentru response si message si se inchide
             * conexiunea */
            free(response);
            free(message);
            close_connection(sockfd);
            continue;
        }

        if (!strcmp("logout\n", buffer)) {
            sockfd = open_connection("34.118.48.238", 8080, AF_INET,
                SOCK_STREAM, 0);

            if (sockfd < 0)  {
                error("error open connection!");
            }

            /* Se creeaza GET request-ul */
            message = compute_get_request("34.118.48.238", 
                "/api/v1/tema/auth/logout", cookie, NULL);

            /* Se trimite mesajul, se primeste raspunsul si raspunsul se
             * afiseaza la tastatura */
            send_to_server(sockfd, message);
            response = receive_from_server(sockfd);
            puts(response);

            /* Se elibereaza memoria pentru response si message si se inchide
             * conexiunea (se golesc si cookie-ul si token-ul) */
            free(response);
            free(message);
            cookie = NULL;
            token = NULL;
            close_connection(sockfd);
            continue;
        }

        printf("Invalid command!\n");
    }

    free(path);
    return 0;
}