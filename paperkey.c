static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <inttypes.h>
#include "packets.h"

enum options
  {
    OPT_HELP=256
  };

static struct option long_options[]=
  {
    {"help",no_argument,NULL,OPT_HELP},
    {NULL,0,NULL,0}
  };

static void
print_hex(const unsigned char *buffer,size_t buflen)
{
  uint32_t crc;
}

static unsigned char *
parse_openpgp(int fd,int packet)
{

}

int
main(int argc,char *argv[])
{
  int arg;
  FILE *file;
  struct packet *packet;
  ssize_t offset;

  while((arg=getopt_long(argc,argv,"h",long_options,NULL))!=-1)
    switch(arg)
      {
      case OPT_HELP:
      case 'h':
      default:
        printf("foo\n");
        exit(0);
      }

  file=fopen("key.gpg","r");
  packet=parse(file,5,0);
  offset=extract_secrets(packet);

  print_packet(packet,offset);

  //parse(stdin,0,0);

  return 0;
}
