/* $Id$ */

#ifndef _PARSE_H_
#define _PARSE_H_

struct packet *parse(FILE *input,unsigned char want,unsigned char stop);
int calculate_fingerprint(struct packet *packet,size_t public_len,
			  unsigned char fingerprint[20]);
ssize_t extract_secrets(struct packet *packet);
struct packet *read_secrets_file(FILE *secrets);

#endif /* !_PARSE_H_ */
