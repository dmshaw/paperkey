static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include "output.h"

extern size_t line_items;
extern enum output_type output_type;
extern FILE *output;

static void
print_hex(const uint8_t *buf,size_t length)
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

	      fprintf(output,"%2u: ",++line);
	    }

	  fprintf(output,"%02X ",buf[i]);
	  checksum+=buf[i];
	}
    }
  else
    fprintf(output,"%04X\n",checksum);
}

void
output_start(unsigned char fingerprint[20])
{
  int i;

  fprintf(output,"# Secret portions of key ");
  
  for(i=0;i<20;i++)
    fprintf(output,"%02X",fingerprint[i]);

  fprintf(output,"\n");

  switch(output_type)
    {
    case BASE16:
      fprintf(output," 0: BASE16\n");
      break;
    }
}

void
output_bytes(const uint8_t *buf,size_t length)
{
  print_hex(buf,length);
}

void
output_length(size_t length)
{
  unsigned char encoded[5];
  /* We use the same 1,3,5 format as OpenPGP */

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
