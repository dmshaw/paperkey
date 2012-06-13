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

#include <config.h>
#include <stdio.h>
#include "packets.h"
#include "output.h"
#include "parse.h"
#include "extract.h"

extern int verbose;

int
extract(FILE *input,const char *outname,enum data_type output_type)
{
  struct packet *packet;
  int offset;
  unsigned char fingerprint[20];
  unsigned char version=0;

  packet=parse(input,5,0);
  if(!packet)
    {
      fprintf(stderr,"Unable to find secret key packet\n");
      return 1;
    }

  offset=extract_secrets(packet);
  if(offset==-1)
    return 1;

  if(verbose>1)
    fprintf(stderr,"Secret offset is %d\n",offset);

  calculate_fingerprint(packet,offset,fingerprint);

  if(verbose)
    {
      fprintf(stderr,"Primary key fingerprint: ");
      print_bytes(stderr,fingerprint,20);
      fprintf(stderr,"\n");
    }

  output_start(outname,output_type,fingerprint);
  output_bytes(&version,1);
  output_bytes(packet->buf,1);
  output_bytes(fingerprint,20);
  output_length16(packet->len-offset);
  output_bytes(&packet->buf[offset],packet->len-offset);

  free_packet(packet);

  while((packet=parse(input,7,5)))
    {
      offset=extract_secrets(packet);

      if(verbose>1)
	fprintf(stderr,"Secret subkey offset is %d\n",offset);

      calculate_fingerprint(packet,offset,fingerprint);

      if(verbose)
	{
	  fprintf(stderr,"Subkey fingerprint: ");
	  print_bytes(stderr,fingerprint,20);
	  fprintf(stderr,"\n");
	}

      output_bytes(packet->buf,1);
      output_bytes(fingerprint,20);
      output_length16(packet->len-offset);
      output_bytes(&packet->buf[offset],packet->len-offset);

      free_packet(packet);
    }

  output_finish();

  if(input==stdin)
    {
      /* Consume everything else on input */
      while((fgetc(input)!=EOF))
	;
    }

  return 0;
}
