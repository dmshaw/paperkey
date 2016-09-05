/*
 * Copyright (C) 2007, 2008, 2009, 2012, 2016 David Shaw <dshaw@jabberwocky.com>
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
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
#include "packets.h"
#include "output.h"

extern unsigned int output_width;
extern char *comment;

static enum data_type output_type;
static FILE *output;
static unsigned int line_items;
static unsigned long all_crc=CRC24_INIT;

#define CRC24_POLY 0x864CFBL

void
do_crc24(unsigned long *crc,const unsigned char *buf,size_t len)
{
  size_t i;

  for(i=0;i<len;i++)
    {
      int j;

      *crc^=buf[i]<<16;
      for(j=0;j<8;j++)
	{
	  *crc<<=1;
	  if(*crc&0x1000000)
	    *crc^=CRC24_POLY;
	}
    }
}

static void
print_base16(const unsigned char *buf,size_t length)
{
  static unsigned long line_crc=CRC24_INIT;
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

	  do_crc24(&line_crc,&buf[i],1);
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

void
output_file_format(FILE *stream,const char *prefix)
{
  fprintf(stream,"%sFile format:\n",prefix);
  fprintf(stream,"%sa) 1 octet:  Version of the paperkey format (currently 0).\n",prefix);
  fprintf(stream,"%sb) 1 octet:  OpenPGP key or subkey version (currently 4)\n",prefix);
  fprintf(stream,"%sc) n octets: Key fingerprint (20 octets for a version 4 key or subkey)\n",prefix);
  fprintf(stream,"%sd) 2 octets: 16-bit big endian length of the following secret data\n",prefix);
  fprintf(stream,"%se) n octets: Secret data: a partial OpenPGP secret key or subkey packet as\n",prefix);
  fprintf(stream,"%s             specified in RFC 4880, starting with the string-to-key usage\n",prefix);
  fprintf(stream,"%s             octet and continuing until the end of the packet.\n",prefix);
  fprintf(stream,"%sRepeat fields b through e as needed to cover all subkeys.\n",prefix);
  fprintf(stream,"%s\n",prefix);
  fprintf(stream,"%sTo recover a secret key without using the paperkey program, use the\n",prefix);
  fprintf(stream,"%skey fingerprint to match an existing public key packet with the\n",prefix);
  fprintf(stream,"%scorresponding secret data from the paper key.  Next, append this secret\n",prefix);
  fprintf(stream,"%sdata to the public key packet.  Finally, switch the public key packet tag\n",prefix);
  fprintf(stream,"%sfrom 6 to 5 (14 to 7 for subkeys).  This will recreate the original secret\n",prefix);
  fprintf(stream,"%skey or secret subkey packet.  Repeat as needed for all public key or subkey\n",prefix);
  fprintf(stream,"%spackets in the public key.  All other packets (user IDs, signatures, etc.)\n",prefix);
  fprintf(stream,"%smay simply be copied from the public key.\n",prefix);
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
    {
      if(type==RAW)
	set_binary_mode(stdout);

      output=stdout;
    }

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
	fprintf(output,"# Base16 data extracted %.24s\n",ctime(&now));
	fprintf(output,"# Created with " PACKAGE_STRING " by David Shaw\n#\n");
	output_file_format(output,"# ");
	fprintf(output,"#\n# Each base16 line ends with a CRC-24 of that line.\n");
	fprintf(output,"# The entire block of data ends with a CRC-24 of the entire block of data.\n\n");
	if(comment)
	  fprintf(output,"# %s\n\n",comment);
      }
      break;
    }

  return 0;
}

ssize_t
output_bytes(const unsigned char *buf,size_t length)
{
  ssize_t ret=-1;

  do_crc24(&all_crc,buf,length);

  switch(output_type)
    {
    case RAW:
      if(buf==NULL)
	{
	  unsigned char crc[3];

	  crc[0]=(all_crc&0xFFFFFFL)>>16;
	  crc[1]=(all_crc&0xFFFFFFL)>>8;
	  crc[2]=(all_crc&0xFFFFFFL);

	  ret=fwrite(crc,1,3,output);
	}
      else
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
output_openpgp_header(unsigned char tag,size_t length)
{
  unsigned char encoded[6];
  size_t bytes;

  /* We use the same "tag under 16, use old-style packets" rule that
     many OpenPGP programs do.  This helps make the resulting key
     byte-for-byte identical.  It's not a guarantee, as it is legal
     for the generating program to use whatever packet style it likes,
     but does help avoid questions why the input to paperkey might not
     equal the output. */

  if(tag<16)
    {
      if(length>65535)
	{
	  encoded[0]=0x80|(tag<<2)|2;
	  encoded[1]=length>>24;
	  encoded[2]=length>>16;
	  encoded[3]=length>>8;
	  encoded[4]=length;
	  bytes=5;
	}
      else if(length>255)
	{
	  encoded[0]=0x80|(tag<<2)|1;
	  encoded[1]=length>>8;
	  encoded[2]=length;
	  bytes=3;
	}
      else
	{
	  encoded[0]=0x80|(tag<<2);
	  encoded[1]=length;
	  bytes=2;
	}
    }
  else
    {
      encoded[0]=0xC0|tag;

      if(length>8383)
	{
	  encoded[1]=0xFF;
	  encoded[2]=length>>24;
	  encoded[3]=length>>16;
	  encoded[4]=length>>8;
	  encoded[5]=length;
	  bytes=6;
	}
      else if(length>191)
	{
	  encoded[1]=192+((length-192)>>8);
	  encoded[2]=(length-192);
	  bytes=3;
	}
      else
	{
	  encoded[1]=length;
	  bytes=2;
	}
    }

  return output_bytes(encoded,bytes);
}

void
output_finish(void)
{
  output_bytes(NULL,0);
}

void
set_binary_mode(FILE *stream)
{
#ifdef _WIN32
  if(_setmode(_fileno(stream),_O_BINARY)==-1)
    {
      fprintf(stderr,"Unable to set stream mode to binary: %s\n",
	      strerror(errno));
      exit(1);
    }
#else
  (void)stream;
#endif
}
