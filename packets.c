static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "packets.h"

#if 0
    Note that the most significant bit is the left-most bit, called bit
    7. A mask for this bit is 0x80 in hexadecimal.

               +---------------+
          PTag |7 6 5 4 3 2 1 0|
               +---------------+
          Bit 7 -- Always one
          Bit 6 -- New packet format if set

    PGP 2.6.x only uses old format packets. Thus, software that
    interoperates with those versions of PGP must only use old format
    packets. If interoperability is not an issue, the new packet format
    is preferred. Note that old format packets have four bits of packet
    tags, and new format packets have six; some features cannot be used
    and still be backward-compatible.

    Also note that packets with a tag greater than or equal to 16 MUST
    use new format packets. The old format packets can only express tags
    less than or equal to 15.

    Old format packets contain:

          Bits 5-2 -- packet tag
          Bits 1-0 - length-type

    New format packets contain:

          Bits 5-0 -- packet tag

#endif

static void
decode_ptag(unsigned char ptag)
{
  unsigned char type;

  if(ptag&0x80)
    {
      type=ptag&0x3F;

      if(!(ptag&0x40))
	type>>2;
    }
}

unsigned char
next_packet(FILE *input)
{
  


}

void
skip_packet(FILE *input)
{


}

unsigned char *
parse(FILE *input,unsigned char want,unsigned char stop)
{
  int byte;
  unsigned char *packet=NULL;

  while((byte=fgetc(input))!=EOF)
    {
      unsigned char type;
      unsigned int length;
      int new;

      if(byte&0x80)
	{
	  int tmp;

	  type=byte&0x3F;

	  if(byte&0x40)
	    {
	      new=1;

	      length=fgetc(input);
	      if(length==EOF)
		goto fail;

	      if(length==255)
		{
		  /* 4-byte length */
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length=tmp<<24;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp<<16;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp<<8;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp;
		}
	      else if(length>=224)
		{
		  /* Partial body length, so fail (keys can't use
		     partial body) */
		}
	      else if(length>=192)
		{
		  /* 2-byte length */
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length=((length-192)<<8)+tmp+192;
		}
	    }
	  else
	    {
	      type>>=2;

	      switch(byte&0x03)
		{
		case 0:
		  /* 1-byte length */
		  length=fgetc(input);
		  if(length==EOF)
		    goto fail;
		  break;

		case 1:
		  /* 2-byte length */
		  length=fgetc(input);
		  if(length==EOF)
		    goto fail;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length<<=8;
		  length|=tmp;
		  break;

		case 2:
		  /* 4-byte length */
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length=tmp<<24;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp<<16;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp<<8;
		  tmp=fgetc(input);
		  if(tmp==EOF)
		    goto fail;
		  length|=tmp;
		  break;

		default:
		  break;
		}
	    }

	  printf("I see type %d length %d\n",type,length);
	}
      else
	{
	  /* error - can't parse */
	}

      if(type==want)
	{
	  packet=malloc(length);
	  if(!packet)
	    goto fail;

	  fread(packet,1,length,input);
	  break;
	}
      else if(type==stop)
	break;
      else
	{
	  /* We don't want it, so skip the packet. */
	  fseek(input,length,SEEK_CUR);
	}
    }

  printf("done\n");

  return packet;

 fail:
  printf("fail\n");
  return NULL;
}

static size_t
mpi_length(unsigned char *header)
{
  return (((header[0]<<8 | header[1]) + 7) / 8) + 2;
}

size_t
extract_secrets(unsigned char *packet)
{
  size_t offset=0;

  /* Secret keys consist of a public key with some secret material
     stuck on the end.  To get to the secrets, we have to skip the
     public stuff. */

  if(packet[0]==3)
    {
      /*
	Jump 7 bytes in.  That gets us past 1 byte of version, 4 bytes
	of timestamp, and 2 bytes of expiration.
      */

      offset=7;

      if(packet[offset]==1)
	{
	  /* Skip 2 MPIs */
	  offset+=mpi_length(&packet[offset]);
	  offset+=mpi_length(&packet[offset]);
	}
      else
	; /* It isn't RSA? */
    }
  else if(packet[0]==4)
    {
      /* Jump 5 bytes in.  That gets us past 1 byte of version, and 4
	 bytes of timestamp. */

      offset=5;

      switch(packet[offset])
	{
	case 1: /* RSA */
	  /* Skip 2 MPIs */
	  offset+=mpi_length(&packet[offset]);
	  offset+=mpi_length(&packet[offset]);
	  break;

	case 2: /* DSA */
	  /* Skip 4 MPIs */
	  offset+=mpi_length(&packet[offset]);
	  offset+=mpi_length(&packet[offset]);
	  offset+=mpi_length(&packet[offset]);
	  offset+=mpi_length(&packet[offset]);
	  break;

	case 3: /* Elgamal */
	  /* Skip 3 MPIs */
	  offset+=mpi_length(&packet[offset]);
	  offset+=mpi_length(&packet[offset]);
	  offset+=mpi_length(&packet[offset]);
	  break;

	default:
	  /* What algorithm? */
	  break;
	}
    }

  return offset;
}

