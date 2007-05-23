/* $Id$ */

#ifndef _OUTPUT_H_
#define _OUTPUT_H_

enum output_type {BASE16,RAW};

#define CRC24_INIT 0xB704CEL
#define CRC24_POLY 0x864CFBL

void do_crc24(unsigned long *crc,unsigned char byte);
void print_bytes(FILE *stream,const unsigned char *buf,size_t length);
void output_start(unsigned char fingerprint[20]);
void output_bytes(const unsigned char *buf,size_t length);
#define output_packet(_packet) output_bytes((_packet)->buf,(_packet)->len)
void output_length16(size_t length);
void output_length(size_t length);
void output_finish(void);

#endif /* !_OUTPUT_H_ */
