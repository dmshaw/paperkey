/* $Id$ */

#ifndef _OUTPUT_H_
#define _OUTPUT_H_

#include <stdint.h>

enum output_type {BASE16};

void print_bytes(FILE *stream,const uint8_t *buf,size_t length);
void output_start(unsigned char fingerprint[20]);
void output_bytes(const uint8_t *buf,size_t length);
void output_length(size_t length);
void output_finish(void);

#endif /* !_OUTPUT_H_ */
