/* $Id$ */

#ifndef _PACKETS_H_
#define _PACKETS_H_

struct packet
{
  unsigned char *buf;
  size_t len;
};

struct packet *parse(FILE *input,unsigned char want,unsigned char stop);
void free_packet(struct packet *packet);
char *find_fingerprint(struct packet *packet,size_t public_len);
void output_fingerprint(struct packet *packet,size_t public_len);
void calculate_fingerprint(struct packet *packet,size_t public_len,
			   unsigned char fingerprint[20]);
ssize_t extract_secrets(struct packet *packet);

#endif /* !_PACKETS_H_ */
