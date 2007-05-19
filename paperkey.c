static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>

enum options
  {
    OPT_HELP=256
  };

static struct option long_options[]=
  {
    {"help",no_argument,NULL,OPT_HELP},
    {NULL,0,NULL,0}
  };

int
main(int argc,char *argv[])
{
  int arg;

  while((arg=getopt_long(argc,argv,"h",long_options,NULL))!=-1)
    switch(arg)
      {
      case OPT_HELP:
      case 'h':
      default:
        printf("foo\n");
        exit(0);
      }

  return 0;
}
