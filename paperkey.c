static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <inttypes.h>
#include "packets.h"

int verbose=0;

enum options
  {
    OPT_HELP=256,
    OPT_VERSION
  };

static struct option long_options[]=
  {
    {"help",no_argument,NULL,OPT_HELP},
    {"version",no_argument,NULL,OPT_VERSION},
    {NULL,0,NULL,0}
  };

int
main(int argc,char *argv[])
{
  int arg;
  FILE *file;
  struct packet *packet;
  ssize_t offset;

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
      }

  file=fopen("key.gpg","r");

  packet=parse(file,5,0);
  offset=extract_secrets(packet);

  if(verbose)
    fprintf(stderr,"Secret offset is %d\n",offset);

  printf("fpr is %s\n",find_fingerprint(packet,offset));

  print_packet(packet,offset);
  free_packet(packet);

  return 0;

  while((packet=parse(file,7,5)))
    {
      offset=extract_secrets(packet);
      print_packet(packet,offset);
      free_packet(packet);
    }




  //parse(stdin,0,0);

  return 0;
}
