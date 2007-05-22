static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
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

static struct key *
extract_key(struct packet *packet,size_t *idx)
{
  struct key *key=NULL;

  /* 1+20+2 == version + fingerprint + length */
  if(*idx+1+20+2<=packet->len)
    {
      if(packet->buf[*idx]==4)
	{
	  unsigned int len;

	  key=xmalloc(sizeof(*key));
	  key->next=NULL;

	  (*idx)++;
	  memcpy(key->fpr,&packet->buf[*idx],20);

	  *idx+=20;

	  len =packet->buf[(*idx)++]<<8;
	  len|=packet->buf[(*idx)++];

	  if(*idx+len<=packet->len)
	    {
	      key->packet=append_packet(NULL,&packet->buf[*idx],len);
	      *idx+=len;
	    }
	  else
	    {
	      free(key);
	      key=NULL;
	    }
	}
    }
  
  return key;
}

static void
free_key(struct key *key)
{
  free_packet(key->packet);
  free(key);
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
		      output_bytes(pubkey->buf,pubkey->len);
		      output_bytes(keyidx->packet->buf,keyidx->packet->len);
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
	      output_bytes(pubkey->buf,pubkey->len);
	    }

	  free_packet(pubkey);
	}
    }
  else
    fprintf(stderr,"Unable to read secrets file\n");

  return;
}

#if 0
void
restore(FILE *pubring,FILE *secrets)
{
  struct packet *secret;

  output_type=RAW;

  secret=read_secrets_file(secrets);
  if(secret)
    {
      struct packet *pubkey;
      unsigned char ptag;
      size_t sidx=0;
      struct key *keys;

      output_start(NULL);

      /* Pull out the fingerprint */
      if(secret->len<21)
	goto fail;

      if(secret->buf[0]!=4)
	goto fail;

      pubkey=find_pubkey(pubring,&secret->buf[1]);

      keys=extract_key(secret,&sidx);
      if(keys)
	{
	  /* Build a list of all subkeys.  We need to do this since
	     the public key we are transforming might have the subkeys
	     in a different order than (or not match subkeys at all
	     with) our secret data. */

	  struct key *walk=keys;

	  while((walk->next=extract_key(secret,&sidx)))
	    walk=walk->next;
	}
      else
	{
	  fprintf(stderr,"Unable to extract primary key from secret data\n");
	  goto fail;
	}

      /* New-style secret primary key */
      ptag=0xC5;
      output_bytes(&ptag,1);
      output_length(pubkey->len+keys->packet->len);
      output_bytes(pubkey->buf,pubkey->len);
      output_bytes(keys->packet->buf,keys->packet->len);
      free_packet(pubkey);

      while((pubkey=parse(pubring,0,6)))
	{
	  if(pubkey->type==14)
	    {
	      /* We found a public subkey.  Get a fingerprint for
		 it. */

	      unsigned char fpr[20];
	      struct key *keyidx;

	      calculate_fingerprint(pubkey,pubkey->len,fpr);

	      /* Do we have a secret key that matches? */
	      for(keyidx=keys->next;keyidx;keyidx=keyidx->next)
		{
		  if(memcmp(fpr,keyidx->fpr,20)==0)
		    {
		      /* Match, so create a secret key. */
		      ptag=0xC7;
		      output_bytes(&ptag,1);
		      output_length(pubkey->len+keyidx->packet->len);
		      output_bytes(pubkey->buf,pubkey->len);
		      output_bytes(keyidx->packet->buf,keyidx->packet->len);
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
	      output_bytes(pubkey->buf,pubkey->len);
	    }

	  free_packet(pubkey);
	}
    }

  return;

 fail:
  fprintf(stderr,"Unable to read secrets file\n");
}
#endif
