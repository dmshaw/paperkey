static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include "packets.h"
#include "output.h"
#include "parse.h"
#include "extract.h"

extern int verbose;

int
extract(FILE *input,const char *outname,enum output_type output_type)
{
  struct packet *packet;
  int offset;
  unsigned char fingerprint[20];

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
