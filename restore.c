static const char RCSID[]="$Id$";

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

int
restore(FILE *pubring,const char *secretname,
	enum data_type input_type,const char *outname)
{
  FILE *secrets;
  struct packet *secret;

  if(input_type==RAW)
    secrets=fopen(secretname,"rb");
  else
    secrets=fopen(secretname,"r");

  if(!secrets)
    {
      fprintf(stderr,"Unable to open secrets file %s: %s\n",
	      secretname,strerror(errno));
      return 1;
    }

  if(input_type==AUTO)
    {
      int test=fgetc(secrets);

      if(test==EOF)
	{
	  fprintf(stderr,"Unable to check type of secrets file %s\n",
		  secretname);
	  return 1;
	}
      else if(isascii(test) && isprint(test))
	{
	  input_type=BASE16;
	  ungetc(test,secrets);
	}
      else
	{
	  input_type=RAW;

	  fclose(secrets);
	  secrets=fopen(secretname,"rb");
	  if(!secrets)
	    {
	      fprintf(stderr,"Unable to reopen secrets file %s: %s\n",
		      secretname,strerror(errno));
	      return 1;
	    }
	}
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
			  output_openpgp_length(pubkey->len
						+keyidx->packet->len);
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
		  output_openpgp_length(pubkey->len);
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
