static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include "packets.h"
#include "output.h"
#include "restore.h"

extern enum output_type output_type;

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
      size_t sidx,secretlen;

      output_start(NULL);

      /* Pull out the fingerprint */
      if(secret->len<21)
	goto fail;

      if(secret->buf[0]!=4)
	goto fail;

      pubkey=find_pubkey(pubring,&secret->buf[1]);

      sidx=21;

      secretlen=secret->buf[sidx++]<<8;
      secretlen|=secret->buf[sidx++];

      /* New-style secret key */
      ptag=0xC5;
      output_bytes(&ptag,1);
      output_length(pubkey->len+secretlen);
      output_bytes(pubkey->buf,pubkey->len);
      output_bytes(&secret->buf[23],secretlen);

      sidx+=secretlen;

      free_packet(pubkey);

      pubkey=parse(pubring,13,0);

      free_packet(pubkey);

      while((pubkey=parse(pubring,14,6)))
	{

	  free_packet(pubkey);
	}
    }

  return;

 fail:
  fprintf(stderr,"Unable to read secrets file\n");
}
