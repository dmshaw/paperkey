/*
 * Copyright (C) 2007, 2008, 2009 David Shaw <dshaw@jabberwocky.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
#include "output.h"
#include "extract.h"
#include "restore.h"

int verbose=0,ignore_crc_error=0;
unsigned int output_width=78;
char *comment=NULL;

enum options
  {
    OPT_HELP=256,
    OPT_VERSION,
    OPT_VERBOSE,
    OPT_OUTPUT,
    OPT_INPUT_TYPE,
    OPT_OUTPUT_TYPE,
    OPT_OUTPUT_WIDTH,
    OPT_SECRET_KEY,
    OPT_PUBRING,
    OPT_SECRETS,
    OPT_IGNORE_CRC_ERROR,
    OPT_FILE_FORMAT,
    OPT_COMMENT
  };

static struct option long_options[]=
  {
    {"help",no_argument,NULL,OPT_HELP},
    {"version",no_argument,NULL,OPT_VERSION},
    {"verbose",no_argument,NULL,OPT_VERBOSE},
    {"output",required_argument,NULL,OPT_OUTPUT},
    {"input-type",required_argument,NULL,OPT_INPUT_TYPE},
    {"output-type",required_argument,NULL,OPT_OUTPUT_TYPE},
    {"output-width",required_argument,NULL,OPT_OUTPUT_WIDTH},
    {"secret-key",required_argument,NULL,OPT_SECRET_KEY},
    {"pubring",required_argument,NULL,OPT_PUBRING},
    {"secrets",required_argument,NULL,OPT_SECRETS},
    {"ignore-crc-error",no_argument,NULL,OPT_IGNORE_CRC_ERROR},
    {"file-format",no_argument,NULL,OPT_FILE_FORMAT},
    {"comment",required_argument,NULL,OPT_COMMENT},
    {NULL,0,NULL,0}
  };

static void
usage(void)
{
  printf("Usage: paperkey [OPTIONS]\n");
  printf("  --help\n");
  printf("  --version\n");
  printf("  --verbose (-v)  be more verbose\n");
  printf("  --output        write output to this file\n");
  printf("  --input-type    auto, base16 or raw (binary)\n");
  printf("  --output-type   base16 or raw (binary)\n");
  printf("  --output-width  maximum width of base16 output\n");
  printf("  --secret-key"
	  "    extract secret data from this secret key\n");
  printf("  --pubring"
	  "       public keyring to find non-secret data\n");
  printf("  --secrets       file containing secret"
	  " data to join with the public key\n");
  printf("  --ignore-crc-error  don't reject corrupted input\n");
  printf("  --file-format   show the paperkey file format\n");
  printf("  --comment       add a comment to the base16 output\n");
}

int
main(int argc,char *argv[])
{
  int arg,err;
  FILE *secret_key,*secrets,*pubring=NULL;
  const char *outname=NULL;
  enum data_type output_type=BASE16;
  enum data_type input_type=AUTO;

#ifdef _WIN32
  if(_setmode(_fileno(stdin),_O_BINARY)==-1)
    {
      fprintf(stderr,"Unable to set stdin mode to binary: %s\n",
	      strerror(errno));
      exit(1);
    }
#endif

  secret_key=secrets=stdin;

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
	printf("%s\n",PACKAGE_STRING);
	printf("%s\n",COPYRIGHT_STRING);
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

      case OPT_INPUT_TYPE:
	if(strcmp(optarg,"auto")==0)
	  input_type=AUTO;
	else if(strcmp(optarg,"base16")==0)
	  input_type=BASE16;
	else if(strcmp(optarg,"raw")==0)
	  input_type=RAW;
	else
	  {
	    fprintf(stderr,"Unknown input type \"%s\"\n",optarg);
	    exit(1);
	  }
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
	secret_key=fopen(optarg,"rb");
	if(!secret_key)
	  {
	    fprintf(stderr,"Unable to open %s: %s\n",optarg,strerror(errno));
	    exit(1);
	  }
	break;

      case OPT_PUBRING:
	pubring=fopen(optarg,"rb");
	if(!pubring)
	  {
	    fprintf(stderr,"Unable to open pubring %s: %s\n",
		    optarg,strerror(errno));
	    exit(1);
	  }
	break;

      case OPT_SECRETS:
	secrets=fopen(optarg,"rb");
	if(!secrets)
	  {
	    fprintf(stderr,"Unable to open %s: %s\n",optarg,strerror(errno));
	    exit(1);
	  }
	break;

      case OPT_IGNORE_CRC_ERROR:
	ignore_crc_error=1;
	break;

      case OPT_FILE_FORMAT:
	output_file_format(stdout,"");
	exit(0);

      case OPT_COMMENT:
	comment=optarg;
	break;
      }

  if(pubring)
    err=restore(pubring,secrets,input_type,outname);
  else
    err=extract(secret_key,outname,output_type);

  return err;
}
