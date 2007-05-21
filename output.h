/* $Id$ */

#ifndef _OUTPUT_H_
#define _OUTPUT_H_

enum output_type {BASE16,RAW};

void print_bytes(FILE *stream,const unsigned char *buf,size_t length);
void output_start(unsigned char fingerprint[20]);
void output_bytes(const unsigned char *buf,size_t length);
void output_length16(size_t length);
void output_length(size_t length);
void output_finish(void);
struct packet *read_secrets_file(FILE *secrets);

#endif /* !_OUTPUT_H_ */
