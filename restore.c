static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "packets.h"
#include "output.h"
#include "restore.h"

extern enum output_type output_type;

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
  size_t idx=0;

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
		  free(newkey);
		  break;
		}

	      newkey->next=key;
	      key=newkey;
	    }
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

void
restore(FILE *pubring,FILE *secrets)
{
  struct packet *secret;

  output_type=RAW;

  secret=read_secrets_file(secrets);
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
	  output_start(NULL);

	  while((pubkey=parse(pubring,0,0)))
	    {
	      unsigned char ptag;

	      if(pubkey->type==6 || pubkey->type==14)
		{
		  /* Public key or subkey */
		  unsigned char fpr[20];
		  struct key *keyidx;

		  if(pubkey->type==6)
		    {
		      if(did_pubkey)
			break;

		      ptag=0xC5;
		      did_pubkey=1;
		    }
		  else
		    ptag=0xC7;

		  calculate_fingerprint(pubkey,pubkey->len,fpr);

		  /* Do we have a secret key that matches? */
		  for(keyidx=keys;keyidx;keyidx=keyidx->next)
		    {
		      if(memcmp(fpr,keyidx->fpr,20)==0)
			{
			  /* Match, so create a secret key. */
			  output_bytes(&ptag,1);
			  output_length(pubkey->len+keyidx->packet->len);
			  output_packet(pubkey);
			  output_packet(keyidx->packet);
			}
		    }
		}
	      else if(pubkey->type==13)
		{
		  /* Copy the usual user ID, sigs, etc, so the key is
		     well-formed */
		  ptag=0xC0|pubkey->type;
		  output_bytes(&ptag,1);
		  output_length(pubkey->len);
		  output_packet(pubkey);
		}

	      free_packet(pubkey);
	    }

	  free_keys(keys);
	}
      else
	fprintf(stderr,"Unable to parse secret data\n");
    }
  else
    fprintf(stderr,"Unable to read secrets file\n");

  return;
}
