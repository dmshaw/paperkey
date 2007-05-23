static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "output.h"
#include "extract.h"
#include "restore.h"

int verbose=0,ignore_crc_error=0;
unsigned int output_width=78;

enum options
  {
    OPT_HELP=256,
    OPT_VERSION,
    OPT_VERBOSE,
    OPT_OUTPUT,
    OPT_OUTPUT_TYPE,
    OPT_OUTPUT_WIDTH,
    OPT_SECRET_KEY,
    OPT_PUBRING,
    OPT_SECRETS,
    OPT_IGNORE_CRC_ERROR
  };

static struct option long_options[]=
  {
    {"help",no_argument,NULL,OPT_HELP},
    {"version",no_argument,NULL,OPT_VERSION},
    {"verbose",no_argument,NULL,OPT_VERBOSE},
    {"output",required_argument,NULL,OPT_OUTPUT},
    {"output-type",required_argument,NULL,OPT_OUTPUT_TYPE},
    {"output-width",required_argument,NULL,OPT_OUTPUT_WIDTH},
    {"secret-key",required_argument,NULL,OPT_SECRET_KEY},
    {"pubring",required_argument,NULL,OPT_PUBRING},
    {"secrets",required_argument,NULL,OPT_SECRETS},
    {"ignore-crc-error",no_argument,NULL,OPT_IGNORE_CRC_ERROR},
    {NULL,0,NULL,0}
  };

static void
usage(void)
{
  printf("Usage: paperkey [OPTIONS]\n");
  printf("  --help\n");
  printf("  --version\n");
  printf("  --verbose\n");
  printf("  --output        write output to this file\n");
  printf("  --output-type   base16 or raw (binary)\n");
  printf("  --output-width  maximum width of base16 output\n");
  printf("  --secret-key"
	  "    extract secret data from this secret key\n");
  printf("  --pubring"
	  "       public keyring to find non-secret data\n");
  printf("  --secrets       text file containing secret"
	  " data to join with the public key\n");
}

int
main(int argc,char *argv[])
{
  int arg,err;
  FILE *secret_key,*pubring=NULL,*secrets=NULL;
  const char *outname=NULL;
  enum output_type output_type=BASE16;

  secret_key=stdin;

  while((arg=getopt_long(argc,argv,"hVv",long_options,NULL))!=-1)
    switch(arg)
      {
      case OPT_HELP:
      case 'h':
      default:
        usage();
        exit(0);

      case OPT_VERSION:
      case 'V':
	printf("paperkey " VERSION "\n");
	printf("Copyright (C) 2007 David Shaw\n");
	printf("This is free software.  You may redistribute copies of it"
	       " under the terms of\n");
	printf("the GNU General Public License"
	       " <http://www.gnu.org/licenses/gpl.html>.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	exit(0);

      case OPT_VERBOSE:
      case 'v':
	verbose++;
	break;

      case OPT_OUTPUT:
	outname=optarg;
	break;

      case OPT_OUTPUT_TYPE:
	if(strcmp(optarg,"base16")==0)
	  output_type=BASE16;
	else if(strcmp(optarg,"raw")==0)
	  output_type=RAW;
	else
	  {
	    fprintf(stderr,"Unknown output type \"%s\"\n",optarg);
	    exit(1);
	  }
	break;

      case OPT_OUTPUT_WIDTH:
	output_width=atoi(optarg);
	break;

      case OPT_SECRET_KEY:
	secret_key=fopen(optarg,"r");
	if(!secret_key)
	  {
	    fprintf(stderr,"Unable to open %s: %s\n",optarg,strerror(errno));
	    exit(1);
	  }
	break;

      case OPT_PUBRING:
	pubring=fopen(optarg,"r");
	if(!pubring)
	  {
	    fprintf(stderr,"Unable to open pubring %s: %s\n",
		    optarg,strerror(errno));
	    exit(1);
	  }
	break;

      case OPT_SECRETS:
	secrets=fopen(optarg,"r");
	if(!secrets)
	  {
	    fprintf(stderr,"Unable to open secrets %s: %s\n",
		    optarg,strerror(errno));
	    exit(1);
	  }
	break;

      case OPT_IGNORE_CRC_ERROR:
	ignore_crc_error=1;
	break;
      }

  if(pubring && secrets)
    err=restore(pubring,secrets,outname);
  else
    err=extract(secret_key,outname,output_type);

  return err;
}
