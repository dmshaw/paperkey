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
static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include "packets.h"
#include "output.h"

extern unsigned int output_width;

static enum data_type output_type;
static FILE *output;
static unsigned int line_items;

void
do_crc24(unsigned long *crc,unsigned char byte)
{
  int j;

  *crc^=byte<<16;
  for(j=0;j<8;j++)
    {
      *crc<<=1;
      if(*crc&0x1000000)
	*crc^=CRC24_POLY;
    }
}

static void
print_base16(const unsigned char *buf,size_t length)
{
  static unsigned long line_crc=CRC24_INIT,all_crc=CRC24_INIT;
  static unsigned int line=0;

  if(buf)
    {
      size_t i;
      static unsigned int offset=0;

      for(i=0;i<length;i++,offset++)
	{
	  if(offset%line_items==0)
	    {
	      if(line)
		{
		  fprintf(output,"%06lX\n",line_crc&0xFFFFFFL);
		  line_crc=CRC24_INIT;
		}

	      fprintf(output,"%3u: ",++line);
	    }

	  fprintf(output,"%02X ",buf[i]);

	  do_crc24(&line_crc,buf[i]);
	  do_crc24(&all_crc,buf[i]);
	}
    }
  else
    {
      fprintf(output,"%06lX\n",line_crc&0xFFFFFFL);
      fprintf(output,"%3u: %06lX\n",line+1,all_crc&0xFFFFFFL);
    }
}

void
print_bytes(FILE *stream,const unsigned char *buf,size_t length)
{
  size_t i;

  for(i=0;i<length;i++)
    fprintf(stream,"%02X",buf[i]);
}

int
output_start(const char *name,enum data_type type,
	     unsigned char fingerprint[20])
{
  if(name)
    {
      if(type==RAW)
	output=fopen(name,"wb");
      else
	output=fopen(name,"w");

      if(!output)
	return -1;
    }
  else
    output=stdout;

  output_type=type;

  switch(type)
    {
    case RAW:
      break;

    case AUTO:
    case BASE16:
      {
	time_t now=time(NULL);

	line_items=(output_width-5-6)/3;
	fprintf(output,"# Secret portions of key ");
	print_bytes(output,fingerprint,20);
	fprintf(output,"\n");
	fprintf(output,"# Base 16 data extracted %.24s\n",ctime(&now));
	fprintf(output,"# Created with " PACKAGE_STRING " by David Shaw\n");
      }
      break;
    }

  return 0;
}

ssize_t
output_bytes(const unsigned char *buf,size_t length)
{
  ssize_t ret=-1;

  switch(output_type)
    {
    case RAW:
      ret=fwrite(buf,1,length,output);
      break;

    case AUTO:
    case BASE16:
      print_base16(buf,length);
      ret=length;
      break;
    }

  return ret;
}

ssize_t
output_length16(size_t length)
{
  unsigned char encoded[2];

  assert(length<=65535);

  encoded[0]=length>>8;
  encoded[1]=length;

  return output_bytes(encoded,2);
}

ssize_t
output_openpgp_length(size_t length)
{
  unsigned char encoded[5];

  if(length>8383)
    {
      encoded[0]=0xFF;
      encoded[1]=length>>24;
      encoded[2]=length>>16;
      encoded[3]=length>>8;
      encoded[4]=length;
      return output_bytes(encoded,5);
    }
  else if(length>191)
    {
      encoded[0]=192+((length-192)>>8);
      encoded[1]=(length-192);
      return output_bytes(encoded,2);
    }
  else
    {
      encoded[0]=length;
      return output_bytes(encoded,1);
    }
}

void
output_finish(void)
{
  switch(output_type)
    {
    case RAW:
      break;

    case AUTO:
    case BASE16:
      print_base16(NULL,0);
      break;
    }
}
