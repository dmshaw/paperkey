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
		  printf("%04X\n",checksum);
		  checksum=0;
		}

	      printf("%2u:",++line);
	    }

	  printf(" %02X",buf[i]);
	  checksum+=buf[i];
	}
    }
  else
    printf("%04X\n",checksum);
}

void
output_start(void)
{
  switch(output_type)
    {
    case BASE16:
      fprintf(output,"BASE16\n");
      break;
    }
}

void
output_bytes(const uint8_t *buf,size_t length)
{
  print_hex(buf,length);
}

void
output_finish(void)
{
  print_hex(NULL,0);
}
