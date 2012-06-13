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
