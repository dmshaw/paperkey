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

#ifndef _PARSE_H_
#define _PARSE_H_

struct packet *parse(FILE *input,unsigned char want,unsigned char stop);
int calculate_fingerprint(struct packet *packet,size_t public_len,
			  unsigned char fingerprint[20]);
ssize_t extract_secrets(struct packet *packet);
struct packet *read_secrets_file(FILE *secrets,enum data_type input_type);

#endif /* !_PARSE_H_ */
