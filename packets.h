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
ssize_t extract_secrets(struct packet *packet);
void print_packet(struct packet *packet,ssize_t offset);

#endif /* !_PACKETS_H_ */
