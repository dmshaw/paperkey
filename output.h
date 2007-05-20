/* $Id$ */

#ifndef _OUTPUT_H_
#define _OUTPUT_H_

#include <stdint.h>

void output_start(void);
void output(const uint8_t *buf,size_t length);
void output_finish(void);

#endif /* !_OUTPUT_H_ */
