/*
 * Copyright (C) 2007 David Shaw <dshaw@jabberwocky.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
/* $Id$ */

#ifndef _OUTPUT_H_
#define _OUTPUT_H_

#include <sys/types.h>

enum data_type {AUTO,BASE16,RAW};

#define CRC24_INIT 0xB704CEL

void do_crc24(unsigned long *crc,const unsigned char *buf,size_t len);
void print_bytes(FILE *stream,const unsigned char *buf,size_t length);
void output_file_format(FILE *stream,const char *prefix);
int output_start(const char *name,enum data_type type,
		 unsigned char fingerprint[20]);
ssize_t output_bytes(const unsigned char *buf,size_t length);
#define output_packet(_packet) output_bytes((_packet)->buf,(_packet)->len)
ssize_t output_length16(size_t length);
ssize_t output_openpgp_length(size_t length);
void output_finish(void);

#endif /* !_OUTPUT_H_ */
