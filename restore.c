/*
 * Copyright (C) 2007, 2012 David Shaw <dshaw@jabberwocky.com>
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
#include <errno.h>
#include <ctype.h>
#include "packets.h"
#include "output.h"
#include "parse.h"
#include "restore.h"

struct key
{
  unsigned char fpr[20];
  struct packet *packet;
  struct key *next;
};

static struct key *
extract_keys(struct packet *packet)
{
  struct key *key=NULL;
  size_t idx=1;

  /* Check the version */
  if(packet->len && packet->buf[0]!=0)
    {
      fprintf(stderr,"Cannot handle secrets file version %d\n",
	      packet->buf[0]);
      return NULL;
    }

  while(idx<packet->len)
    {
      /* 1+20+2 == version + fingerprint + length */
      if(idx+1+20+2<=packet->len)
	{
	  if(packet->buf[idx]==4)
	    {
	      unsigned int len;
	      struct key *newkey;

	      newkey=xmalloc(sizeof(*newkey));
	      newkey->next=NULL;

	      idx++;
	      memcpy(newkey->fpr,&packet->buf[idx],20);

	      idx+=20;

	      len =packet->buf[idx++]<<8;
	      len|=packet->buf[idx++];

	      if(idx+len<=packet->len)
		{
		  newkey->packet=append_packet(NULL,&packet->buf[idx],len);
		  idx+=len;
		}
	      else
		{
		  fprintf(stderr,"Warning: Short data in secret image\n");
		  free(newkey);
		  break;
		}

	      newkey->next=key;
	      key=newkey;
	    }
	  else
	    {
	      fprintf(stderr,"Warning: Corrupt data in secret image\n");
	      break;
	    }
	}
      else
	{
	  fprintf(stderr,"Warning: Short header in secret image\n");
	  break;
	}
    }
  
  return key;
}

static void
free_keys(struct key *key)
{
  while(key)
    {
      struct key *keytmp=key;
      free_packet(key->packet);
      key=key->next;
      free(keytmp);
    }
}

int
restore(FILE *pubring,FILE *secrets,
	enum data_type input_type,const char *outname)
{
  struct packet *secret;

  if(input_type==AUTO)
    {
      int test=fgetc(secrets);

      if(test==EOF)
	{
	  fprintf(stderr,"Unable to check type of secrets file\n");
	  return 1;
	}
      else if(isascii(test) && isprint(test))
	input_type=BASE16;
      else
	input_type=RAW;

      ungetc(test,secrets);
    }

  secret=read_secrets_file(secrets,input_type);
  if(secret)
    {
      struct packet *pubkey;
      struct key *keys;
      int did_pubkey=0;

      /* Build a list of all keys.  We need to do this since the
	 public key we are transforming might have the subkeys in a
	 different order than (or not match subkeys at all with) our
	 secret data. */

      keys=extract_keys(secret);
      if(keys)
	{
	  output_start(outname,RAW,NULL);

	  while((pubkey=parse(pubring,0,0)))
	    {
	      unsigned char ptag;

	      if(pubkey->type==6 || pubkey->type==14)
		{
		  /* Public key or subkey */
		  unsigned char fpr[20];
		  struct key *keyidx;

		  if(pubkey->type==6 && did_pubkey)
		    break;

		  calculate_fingerprint(pubkey,pubkey->len,fpr);

		  /* Do we have a secret key that matches? */
		  for(keyidx=keys;keyidx;keyidx=keyidx->next)
		    {
		      if(memcmp(fpr,keyidx->fpr,20)==0)
			{
			  if(pubkey->type==6)
			    {
			      ptag=5;
			      did_pubkey=1;
			    }
			  else
			    ptag=7;

			  /* Match, so create a secret key. */
			  output_openpgp_header(ptag,pubkey->len
						+keyidx->packet->len);
			  output_packet(pubkey);
			  output_packet(keyidx->packet);
			}
		    }
		}
	      else if(did_pubkey)
		{
		  /* Copy the usual user ID, sigs, etc, so the key is
		     well-formed. */
		  output_openpgp_header(pubkey->type,pubkey->len);
		  output_packet(pubkey);
		}

	      free_packet(pubkey);
	    }

	  free_keys(keys);
	}
      else
	{
	  fprintf(stderr,"Unable to parse secret data\n");
	  return 1;
	}
    }
  else
    {
      fprintf(stderr,"Unable to read secrets file\n");
      return 1;
    }

  return 0;
}
