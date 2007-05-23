/* $Id$ */

#ifndef _PACKETS_H_
#define _PACKETS_H_

#include <sys/types.h>

struct packet
{
  unsigned char type;
  unsigned char *buf;
  /* The length the data we've put into buf. */
  size_t len;
  /* The length we've malloced for buf. */
  size_t size;
};

void *xrealloc(void *ptr,size_t size);
#define xmalloc(_size) xrealloc(NULL,_size)
struct packet *append_packet(struct packet *packet,
			     unsigned char *buf,size_t len);
void free_packet(struct packet *packet);

#endif /* !_PACKETS_H_ */
