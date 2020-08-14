#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#define MAX_CLIENT 30
#define MAX_CM 2000

static char *rand_string(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWYZ0123456789";
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;
}

int main(int argc, char **argv) {

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == -1) {
    printf("Could not create socket\n");
    return -1;
  }
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) <0) {
    perror("reuse failed\n");
    return -1;
  }

  struct sockaddr_in srv;
  srv.sin_family = AF_INET;
  srv.sin_addr.s_addr = INADDR_ANY;
  srv.sin_port = htons(80);

  int srvlen = sizeof(srv);

  if (bind(s, (struct sockaddr *) &srv, sizeof(srv)) < 0) {
    perror("bind failed\n");
    return -1;
  }

  listen(s, 5);

  int new_s;
  while (1) {
    new_s = accept(s, (struct sockaddr *) &srv, (socklen_t*) &srvlen);
    if (new_s == -1) {
      perror("accept");
      continue;
    }

    if (!fork()) {
      close(s);

      char cm[MAX_CM];
      recv(new_s, cm, MAX_CM, 0);

      char idx[16];
      memset(idx, 0, 16);

      char *resp = "HTTP/1.1 200 OK\nServer: srv\nContent-Type: video/mp2t\n\n";
      int resplen = strlen(resp);
      memcpy(cm, resp, resplen);
      rand_string(cm+resplen, MAX_CM-resplen);
      cm[MAX_CM] = '\0';
      send(new_s, cm, MAX_CM, 0);

      unsigned int i = 0;
      while (1) {
        sprintf(cm, "=%010d=", i);
        i++;
        rand_string(cm+12, MAX_CM-12);
        send(new_s, cm, MAX_CM, 0);
      }

      exit(0);
    }
    close(new_s);
  }
  return 0;
}

