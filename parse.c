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
#include "sha1.h"
#include "packets.h"
#include "output.h"
#include "parse.h"

extern int verbose;
extern int ignore_crc_error;

struct packet *
parse(FILE *input,unsigned char want,unsigned char stop)
{
  int byte;
  struct packet *packet=NULL;

  while((byte=fgetc(input))!=EOF)
    {
      unsigned char type;
      unsigned int length;

      if(byte&0x80)
	{
	  int tmp;

	  type=byte&0x3F;

	  /* Old-style packet type */
	  if(!(byte&0x40))
	    type>>=2;

	  if(type==stop)
	    {
	      ungetc(byte,input);
	      break;
	    }

	  if(byte&0x40)
	    {
	      /* New-style packets */
	      byte=fgetc(input);
	      if(byte==EOF)
		goto fail;

	      if(byte==255)
		{
		  /* 4-byte length */
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length=tmp<<24;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp<<16;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp<<8;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp;
		}
	      else if(byte>=224)
		{
		  /* Partial body length, so fail (keys can't use
		     partial body) */
		  fprintf(stderr,"Invalid partial packet encoding\n");
		  goto fail;
		}
	      else if(byte>=192)
		{
		  /* 2-byte length */
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length=((byte-192)<<8)+tmp+192;
		}
	      else
		length=byte;
	    }
	  else
	    {
	      /* Old-style packets */
	      switch(byte&0x03)
		{
		case 0:
		  /* 1-byte length */
		  byte=fgetc(input);
		  if(byte==EOF)
		    goto fail;
		  length=byte;
		  break;

		case 1:
		  /* 2-byte length */
		  byte=fgetc(input);
		  if(byte==EOF)
		    goto fail;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length=byte<<8;
		  length|=tmp;
		  break;

		case 2:
		  /* 4-byte length */
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length=tmp<<24;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp<<16;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp<<8;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp;
		  break;

		default:
		  fprintf(stderr,"Error: unable to parse old-style length\n");
		  goto fail;
		}
	    }

	  if(verbose>1)
	    fprintf(stderr,"Found packet of type %d, length %d\n",type,length);
	}
      else
	{
	  fprintf(stderr,"Error: unable to parse OpenPGP packets\n");
	  goto fail;
	}

      if(want==0 || type==want)
	{
	  packet=xmalloc(sizeof(*packet));
	  packet->type=type;
	  packet->buf=xmalloc(length);
	  packet->len=length;
	  packet->size=length;
	  fread(packet->buf,1,packet->len,input);
	  break;
	}
      else
	{
	  /* We don't want it, so skip the packet.  We don't use fseek
	     here since the input might be on stdin and that isn't
	     seekable. */

	  size_t i;

	  for(i=0;i<length;i++)
	    fgetc(input);
	}
    }

  return packet;

 fail:
  return NULL;
}

int
calculate_fingerprint(struct packet *packet,size_t public_len,
		      unsigned char fingerprint[20])
{
  if(packet->buf[0]==3)
    {
      return -1;
    }
  else if(packet->buf[0]==4)
    {
      struct sha1_ctx sha;
      unsigned char head[3];

      sha1_init_ctx(&sha);

      head[0]=0x99;
      head[1]=public_len>>8;
      head[2]=public_len&0xFF;

      sha1_process_bytes(head,3,&sha);
      sha1_process_bytes(packet->buf,public_len,&sha);
      sha1_finish_ctx(&sha,fingerprint);
    }

  return 0;
}

#define MPI_LENGTH(_start) (((((_start)[0]<<8 | (_start)[1]) + 7) / 8) + 2)

ssize_t
extract_secrets(struct packet *packet)
{
  size_t offset;

  if(packet->len==0)
    return -1;

  /* Secret keys consist of a public key with some secret material
     stuck on the end.  To get to the secrets, we have to skip the
     public stuff. */

  if(packet->buf[0]==3)
    {
      fprintf(stderr,"Version 3 (PGP 2.x style) keys are not supported.\n");
      return -1;
    }
  else if(packet->buf[0]==4)
    {
      /* Jump 5 bytes in.  That gets us past 1 byte of version, and 4
	 bytes of timestamp. */

      offset=5;
    }
  else
    return -1;

  if(packet->len<=offset)
    return -1;

  switch(packet->buf[offset++])
    {
    case 1: /* RSA */
      /* Skip 2 MPIs */
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      break;

    case 16: /* Elgamal */
      /* Skip 3 MPIs */
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      break;

    case 17: /* DSA */
      /* Skip 4 MPIs */
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      break;

    default:
      /* What algorithm? */
      fprintf(stderr,"Unable to parse algorithm %u\n",packet->buf[offset-1]);
      return -1;
    }

  return offset;
}

struct packet *
read_secrets_file(FILE *secrets,enum data_type input_type)
{
  struct packet *packet=NULL;

  if(input_type==RAW)
    {
      unsigned char buffer[1024];
      size_t got;

      while((got=fread(buffer,1,1024,secrets)))
	packet=append_packet(packet,buffer,got);

      if(got==0 && !feof(secrets))
	{
	  fprintf(stderr,"Error: unable to read secrets file\n");
	  free_packet(packet);
	  return NULL;
	}
    }
  else
    {
      char line[1024];
      int final_crc=0;
      unsigned int next_linenum=1;
      unsigned long all_crc=CRC24_INIT;

      while(fgets(line,1024,secrets))
	{
	  unsigned int linenum,did_digit=0;
	  unsigned long line_crc=CRC24_INIT;
	  char *tok;

	  if(line[0]=='#')
	    continue;

	  linenum=atoi(line);
	  if(linenum!=next_linenum)
	    {
	      fprintf(stderr,"Error: missing line number %u\n",next_linenum);
	      free_packet(packet);
	      return NULL;
	    }
	  else
	    next_linenum=linenum+1;

	  tok=strchr(line,':');
	  if(tok)
	    {
	      tok=strchr(tok,' ');

	      while(tok)
		{
		  char *next;

		  while(*tok==' ')
		    tok++;

		  next=strchr(tok,' ');

		  if(next==NULL)
		    {
		      /* End of line, so check the CRC. */
		      unsigned long new_crc;

		      if(sscanf(tok,"%06lX",&new_crc))
			{
			  if(did_digit)
			    {
			      if((new_crc&0xFFFFFFL)!=(line_crc&0xFFFFFFL))
				{
				  fprintf(stderr,"CRC on line %d does not"
					  " match (%06lX!=%06lX)\n",linenum,
					  new_crc&0xFFFFFFL,
					  line_crc&0xFFFFFFL);
				  if(!ignore_crc_error)
				    {
				      free_packet(packet);
				      return NULL;
				    }
				}
			    }
			  else
			    {
			      final_crc=1;
			      if((new_crc&0xFFFFFFL)!=(all_crc&0xFFFFFFL))
				{
				  fprintf(stderr,"CRC of secret does not"
					  " match (%06lX!=%06lX)\n",
					  new_crc&0xFFFFFFL,
					  line_crc&0xFFFFFFL);
				  if(!ignore_crc_error)
				    {
				      free_packet(packet);
				      return NULL;
				    }
				}
			    }
			}
		    }
		  else
		    {
		      unsigned int digit;

		      if(sscanf(tok,"%02X",&digit))
			{
			  unsigned char d=digit;
			  packet=append_packet(packet,&d,1);
			  do_crc24(&line_crc,d);
			  do_crc24(&all_crc,d);
			  did_digit=1;
			}
		    }

		  tok=next;
		}
	    }
	  else
	    {
	      fprintf(stderr,"No colon ':' found in line %u\n",linenum);
	      free_packet(packet);
	      return NULL;
	    }
	}

      if(!final_crc)
	{
	  fprintf(stderr,"CRC of secret is missing\n");
	  if(!ignore_crc_error)
	    {
	      free_packet(packet);
	      return NULL;
	    }
	}
    }

  return packet;
}
