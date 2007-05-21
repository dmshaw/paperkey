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
    OPT_OUTPUT
  };

static struct option long_options[]=
  {
    {"help",no_argument,NULL,OPT_HELP},
    {"version",no_argument,NULL,OPT_VERSION},
    {"output",required_argument,NULL,OPT_OUTPUT},
    {NULL,0,NULL,0}
  };

int
main(int argc,char *argv[])
{
  int arg;
  FILE *file;
  struct packet *packet;
  ssize_t offset;
  unsigned char fingerprint[20];

  output=stdout;

  while((arg=getopt_long(argc,argv,"hv",long_options,NULL))!=-1)
    switch(arg)
      {
      case OPT_HELP:
      case 'h':
      default:
        printf("foo\n");
        exit(0);

      case OPT_VERSION:
      case 'v':
	printf("paperkey " VERSION "\n");
	exit(0);

      case OPT_OUTPUT:
	output=fopen(optarg,"w");
	if(!output)
	  {
	    fprintf(stderr,"Unable to open %s: %s\n",optarg,strerror(errno));
	    exit(1);
	  }
	break;

      }

  file=fopen("key.gpg","r");

  packet=parse(file,5,0);
  offset=extract_secrets(packet);

  if(verbose)
    fprintf(stderr,"Secret offset is %d\n",offset);

  calculate_fingerprint(packet,offset,fingerprint);

  output_start(fingerprint);

  output_bytes(packet->buf,1);
  output_bytes(fingerprint,20);
  output_length(packet->len-offset);
  output_bytes(&packet->buf[offset],packet->len-offset);

  output_finish();

  free_packet(packet);

  return 0;

  while((packet=parse(file,7,5)))
    {
      offset=extract_secrets(packet);
      //print_packet(packet,offset);
      free_packet(packet);
    }




  //parse(stdin,0,0);

  return 0;
}
