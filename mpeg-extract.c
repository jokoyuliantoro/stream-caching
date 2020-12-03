#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_PAYLOAD_LEN 1500

int main(int argc, char **argv) {
  int c;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *fni = NULL;
  char *fno = NULL;
  struct pcap_pkthdr hdr;
  int i;
  struct in_addr ip4a;
  char *ip4src;
  pcap_t *pf;
  const u_char *p;

  FILE *fp;
  int iphdrlen;
  int iplen;
  int l2hdrlen;
  u_char payload[MAX_PAYLOAD_LEN];
  int payloadlen;
  int tcphdrlen;

  while ((c = getopt(argc, argv, "f:o:")) != -1) {
    switch (c) {
      case 'f':
        fni = optarg;
        break;
      case 'o':
        fno = optarg;
        break;
      default:
        fprintf(stderr, "Err: Unknown option: -%c\n", optopt);
        return 0;
    }
  }

  if (fni == NULL) {
    fprintf(stderr, "Err: Need input filename using -f.\n");
    return 0;
  }

  if (fno == NULL) {
    fprintf(stderr, "Err: Need output filename using -o.\n");
    return 0;
  }

  printf("input filename: %s\n", fni);
  printf("output filename: %s\n", fno);

  pf = pcap_open_offline(fni, errbuf);

  if (pf == NULL) {
    fprintf(stderr, "Err: Failed to open file: %s\n", errbuf);
    return 0;
  }

  i = 1;
  fp = fopen(fno, "wb");
  while ((p = pcap_next(pf, &hdr)) != NULL) {
    if ((p[0x0c]<<8)+p[0x0d] == 0x0800) {
      l2hdrlen = 14;
    } else {
      fprintf(stderr, "Err: Packet is not IPv4: 0x%04X\n", (p[0x0c]<<8)+p[0x0d]);
      return 1;
    }

    ip4a.s_addr = p[0x1a] + (p[0x1b]<<8) + (p[0x1c]<<16) + (p[0x1d]<<24);
    ip4src = inet_ntoa(ip4a);
    if (i>4 && !strcmp(ip4src, "185.132.179.104")) {
      iphdrlen = (p[0x0e] & 0x0f) << 2;
      iplen = (p[0x10]<<8) + p[0x11];
      tcphdrlen = (p[0x2e] & 0xf0) >> 2;
      payloadlen = iplen - iphdrlen - tcphdrlen;

      if (iplen <= MAX_PAYLOAD_LEN) {
        memcpy(payload, p + l2hdrlen + iphdrlen + tcphdrlen, payloadlen);
        payload[payloadlen+1] = 0;
        fwrite(payload, payloadlen, 1, fp);
      } else {
        fprintf(stderr, "Err: IP packet length is beyond %i: %i\n", MAX_PAYLOAD_LEN, iplen);
        return 1;
      }
    }

    i++;
  }
  fclose(fp);
  printf("i: %i\n", i);

  return 0;
}
