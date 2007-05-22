/* $Id$ */

#ifndef _PACKETS_H_
#define _PACKETS_H_

struct packet
{
  unsigned char type;
  unsigned char *buf;
  /* The length the data we've put into buf. */
  size_t len;
  /* The length we've malloced for buf. */
  size_t size;
};

struct packet *parse(FILE *input,unsigned char want,unsigned char stop);
struct packet *append_packet(struct packet *packet,
			     unsigned char *buf,size_t len);
void free_packet(struct packet *packet);
int calculate_fingerprint(struct packet *packet,size_t public_len,
			  unsigned char fingerprint[20]);
ssize_t extract_secrets(struct packet *packet);
struct packet * find_pubkey(FILE *pubring,unsigned char fpr[20]);

#endif /* !_PACKETS_H_ */
