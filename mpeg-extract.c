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
  int j;
  struct in_addr ip4a;
  char *ip4src;
  char *ip4src_in;
  pcap_t *pf;
  const u_char *p;
  const u_char *p_payload;

  FILE *fp;
  int iphdrlen;
  int iplen;
  int l2hdrlen;
  u_char payload[MAX_PAYLOAD_LEN];
  int payloadlen;
  int tcphdrlen;

  while ((c = getopt(argc, argv, "f:o:s:")) != -1) {
    switch (c) {
      case 'f':
        fni = optarg;
        break;
      case 'o':
        fno = optarg;
        break;
      case 's':
        ip4src_in = optarg;
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

  if (ip4src_in == NULL) {
    fprintf(stderr, "Err: Need IPv4 source address identifier using -s.\n");
    return 0;
  }

  printf("input filename: %s\n", fni);
  printf("output filename: %s\n", fno);
  printf("ipv4 source: %s\n", ip4src_in);

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
    if (i>4 && !strcmp(ip4src, ip4src_in)) {
      iphdrlen = (p[0x0e] & 0x0f) << 2;
      iplen = (p[0x10]<<8) + p[0x11];
      tcphdrlen = (p[0x2e] & 0xf0) >> 2;
      payloadlen = iplen - iphdrlen - tcphdrlen;
      p_payload = p + l2hdrlen + iphdrlen + tcphdrlen;

      if (p_payload[0]=='H' && p_payload[1]=='T' && p_payload[2]=='T' && p_payload[3]=='P') {
        printf("%i: found http header, checking the real payload..\n", i);
        const u_char *p_real_payload = p_payload;
        j = 0;
        while (j < (payloadlen-4)) {
          p_real_payload++;
          if (p_real_payload[0]==0x0d && p_real_payload[1]==0x0a && p_real_payload[2]==0x0d && p_real_payload[3]==0x0a) {
            p_payload = p_real_payload + 4;
            payloadlen -= j;
            j = payloadlen;
          }
          j++;
        }
      }

      if (iplen <= MAX_PAYLOAD_LEN) {
        memcpy(payload, p_payload, payloadlen);
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
