static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "packets.h"
#include "output.h"

int verbose=0;
unsigned int output_width=78;
enum output_type output_type=BASE16;
FILE *output=NULL;

enum options
  {
    OPT_HELP=256,
    OPT_VERSION,
    OPT_VERBOSE,
    OPT_OUTPUT,
    OPT_OUTPUT_WIDTH,
    OPT_SECRET_KEY,
    OPT_PUBRING,
    OPT_SECRETS
  };

static struct option long_options[]=
  {
    {"help",no_argument,NULL,OPT_HELP},
    {"version",no_argument,NULL,OPT_VERSION},
    {"verbose",no_argument,NULL,OPT_VERBOSE},
    {"output",required_argument,NULL,OPT_OUTPUT},
    {"output-width",required_argument,NULL,OPT_OUTPUT_WIDTH},
    {"secret-key",required_argument,NULL,OPT_SECRET_KEY},
    {"pubring",required_argument,NULL,OPT_PUBRING},
    {"secrets",required_argument,NULL,OPT_SECRETS},
    {NULL,0,NULL,0}
  };

static void
usage(void)
{
  printf("Usage: paperkey [OPTIONS]\n");
  printf("  --help\n");
  printf("  --version\n");
  printf("  --output        write output to this file\n");
  printf("  --output-width  maximum width of the text output\n");
  printf("  --secret-key"
	  "    extract secret data from this secret key\n");
  printf("  --pubring"
	  "       public keyring to find non-secret data\n");
  printf("  --secrets       text file containing secret"
	  " data to join with the public key\n");
}

static void
extract(FILE *input)
{
  struct packet *packet;
  int offset;
  unsigned char fingerprint[20];

  packet=parse(input,5,0);
  if(!packet)
    {
      fprintf(stderr,"Unable to find secret key packet\n");
      exit(1);
    }

  offset=extract_secrets(packet);
  if(offset==-1)
    exit(1);

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
}

static void
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
    }

  return;

 fail:
  fprintf(stderr,"Unable to read secrets file\n");
}

int
main(int argc,char *argv[])
{
  int arg;
  FILE *secret_key,*pubring=NULL,*secrets=NULL;

  secret_key=stdin;
  output=stdout;

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
	output=fopen(optarg,"w");
	if(!output)
	  {
	    fprintf(stderr,"Unable to open %s: %s\n",optarg,strerror(errno));
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
      }

  if(pubring && secrets)
    restore(pubring,secrets);
  else
    extract(secret_key);

  return 0;
}
