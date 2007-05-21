static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "packets.h"
#include "output.h"

extern size_t output_width;
extern enum output_type output_type;
extern FILE *output;

static size_t line_items;

static void
print_hex(const unsigned char *buf,size_t length)
{
  static size_t checksum=0;

  if(buf)
    {
      size_t i;
      static size_t line=0;
      static size_t offset=0;

      for(i=0;i<length;i++,offset++)
	{
	  if(offset%line_items==0)
	    {
	      if(line)
		{
		  fprintf(output,"%04X\n",checksum);
		  checksum=0;
		}

	      fprintf(output,"%3u: ",++line);
	    }

	  fprintf(output,"%02X ",buf[i]);
	  checksum+=buf[i];
	}
    }
  else
    fprintf(output,"%04X\n",checksum);
}

void
print_bytes(FILE *stream,const unsigned char *buf,size_t length)
{
  size_t i;

  for(i=0;i<length;i++)
    fprintf(stream,"%02X",buf[i]);
}

void
output_start(unsigned char fingerprint[20])
{
  fprintf(output,"# Secret portions of key ");

  print_bytes(output,fingerprint,20);

  fprintf(output,"\n");

  switch(output_type)
    {
    case BASE16:
      line_items=(output_width-5-4)/3;
      fprintf(output,"%3u: BASE16\n",0);
      break;
    }
}

void
output_bytes(const unsigned char *buf,size_t length)
{
  print_hex(buf,length);
}

/* We use the same 1,2,5 format as OpenPGP */
void
output_length(size_t length)
{
  unsigned char encoded[5];

  if(length>8383)
    {
      encoded[0]=0xFF;
      encoded[1]=length>>24;
      encoded[2]=length>>16;
      encoded[3]=length>>8;
      encoded[4]=length;
      output_bytes(encoded,5);
    }
  else if(length>191)
    {
      encoded[0]=192+((length-192)>>8);
      encoded[1]=(length-192);
      output_bytes(encoded,2);
    }
  else
    {
      encoded[0]=length;
      output_bytes(encoded,1);
    }
}

void
output_finish(void)
{
  print_hex(NULL,0);
}

struct packet *
read_secrets_file(FILE *secrets)
{
  struct packet *packet=NULL;
  char line[1024];
  int next_linenum=0;

  while(fgets(line,1024,secrets))
    {
      int linenum;
      char *ptr=line,*tok;

      if(line[0]=='#')
	continue;

      linenum=atoi(ptr);
      if(linenum!=next_linenum)
	{
	  fprintf(stderr,"Error: missing line number %d\n",next_linenum);
	  free_packet(packet);
	  return NULL;
	}
      else
	next_linenum=linenum+1;

      ptr=strchr(line,':');
      if(ptr)
	{
	  ptr++;

	  line[strlen(line)-1]='\0';

	  while((tok=strsep(&ptr," ")))
	    {
	      if(tok[0]=='\0')
		continue;

	      if(linenum==0 && strcmp("BASE16",tok)!=0)
		{
		  fprintf(stderr,"No BASE16 specifier\n");
		  free_packet(packet);
		  return NULL;
		}

	      if(ptr==NULL)
		{
		  /* Checksum */

		}
	      else
		{
		  unsigned int digit;

		  if(sscanf(tok,"%02X",&digit))
		    {
		      unsigned char d=digit;
		      packet=append_packet(packet,&d,1);
		    }
		}
	    }
	}
      else
	{
	  fprintf(stderr,"No colon ':' found in line %d\n",linenum);
	  free_packet(packet);
	  return NULL;
	}
    }

  return packet;
}
