static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h"
#include "output.h"
#include "packets.h"

extern int verbose;

void *
xrealloc(void *ptr,size_t size)
{
  ptr=realloc(ptr,size);
  if(!ptr)
    {
      fprintf(stderr,"Unable to allocate memory\n");
      abort();
    }

  return ptr;
}

struct packet *
append_packet(struct packet *packet,unsigned char *buf,size_t len)
{
  if(packet)
    {
      while(packet->size-packet->len<len)
	{
	  packet->size+=100;
	  packet->buf=xrealloc(packet->buf,packet->size);
	}

      memcpy(&packet->buf[packet->len],buf,len);
      packet->len+=len;
    }
  else
    {
      packet=xmalloc(sizeof(*packet));
      packet->type=0;
      packet->buf=xmalloc(len);
      packet->len=len;
      packet->size=len;

      memcpy(packet->buf,buf,len);
    }

  return packet;
}

void
free_packet(struct packet *packet)
{
  if(packet)
    {
      free(packet->buf);
      free(packet);
    }
}
