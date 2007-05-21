static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "packets.h"
#include "output.h"

int verbose=0;
size_t line_items=20;
enum output_type output_type=BASE16;
FILE *output=NULL;

enum options
  {
    OPT_HELP=256,
    OPT_VERSION,
    OPT_VERBOSE,
    OPT_OUTPUT,
    OPT_SECRET_KEY
  };

static struct option long_options[]=
  {
    {"help",no_argument,NULL,OPT_HELP},
    {"version",no_argument,NULL,OPT_VERSION},
    {"verbose",no_argument,NULL,OPT_VERBOSE},
    {"output",required_argument,NULL,OPT_OUTPUT},
    {"secret-key",required_argument,NULL,OPT_SECRET_KEY},
    {NULL,0,NULL,0}
  };

int
main(int argc,char *argv[])
{
  int arg;
  FILE *input;
  struct packet *packet;
  ssize_t offset;
  unsigned char fingerprint[20];

  input=stdin;
  output=stdout;

  while((arg=getopt_long(argc,argv,"hVv",long_options,NULL))!=-1)
    switch(arg)
      {
      case OPT_HELP:
      case 'h':
      default:
        printf("foo\n");
        exit(0);

      case OPT_VERSION:
      case 'V':
	printf("paperkey " VERSION "\n");
	exit(0);

      case OPT_VERBOSE:
      case 'v':
	verbose++;
	break;

      case OPT_OUTPUT:
	output=fopen(optarg,"w");
	if(!output)
	  {
	    fprintf(stderr,"Unable to open %s: %s\n",optarg,strerror(errno));
	    exit(1);
	  }
	break;

      case OPT_SECRET_KEY:
	input=fopen(optarg,"r");
	if(!input)
	  {
	    fprintf(stderr,"Unable to open %s: %s\n",optarg,strerror(errno));
	    exit(1);
	  }
	break;
      }

  packet=parse(input,5,0);
  if(!packet)
    exit(1);

  offset=extract_secrets(packet);

  if(verbose>1)
    fprintf(stderr,"Secret offset is %d\n",offset);

  calculate_fingerprint(packet,offset,fingerprint);

  if(verbose)
    {
      fprintf(stderr,"Primary key fingerprint: ");
      print_bytes(stderr,fingerprint,20);
      fprintf(stderr,"\n");
    }

  output_start(fingerprint);

  output_bytes(packet->buf,1);
  output_bytes(fingerprint,20);
  output_length(packet->len-offset);
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
      output_length(packet->len-offset);
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
