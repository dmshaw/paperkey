/* $Id$ */

#ifndef _PACKETS_H_
#define _PACKETS_H_

unsigned char *parse(FILE *input,unsigned char want,unsigned char stop);
size_t extract_secrets(unsigned char *packet);

#endif /* !_PACKETS_H_ */
