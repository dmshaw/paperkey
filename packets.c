static const char RCSID[]="$Id$";

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha1.h"
#include "output.h"
#include "packets.h"

extern int verbose;

struct packet *
parse(FILE *input,unsigned char want,unsigned char stop)
{
  int byte;
  struct packet *packet=NULL;

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
		  fprintf(stderr,"Error: unable to parse old-style length\n");
		  goto fail;
		}
	    }

	  if(verbose)
	    fprintf(stderr,"Found packet of type %d, length %d\n",type,length);
	}
      else
	{
	  fprintf(stderr,"Error: unable to parse OpenPGP packets\n");
	  goto fail;
	}

      if(type==want)
	{
	  packet=malloc(sizeof(*packet));
	  if(!packet)
	    goto fail;

	  packet->buf=malloc(length);
	  if(!packet->buf)
	    {
	      free(packet);
	      goto fail;
	    }

	  packet->len=length;

	  fread(packet->buf,1,packet->len,input);
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

  return packet;

 fail:
  return NULL;
}

void
free_packet(struct packet *packet)
{
  free(packet->buf);
  free(packet);
}

char *
find_fingerprint(struct packet *packet,size_t public_len)
{
  char *fpr=NULL;

  if(packet->buf[0]==3)
    {
      
    }
  else if(packet->buf[0]==4)
    {
      SHA1Context sha;
      unsigned char head[3],fingerprint[20];

      if(SHA1Reset(&sha))
	return NULL;

      head[0]=0x99;
      head[1]=public_len>>8;
      head[2]=public_len&0xFF;

      SHA1Input(&sha,head,3);
      SHA1Input(&sha,packet->buf,public_len);
      SHA1Result(&sha,fingerprint);

      fpr=malloc(41);
      if(fpr)
	{
	  int i;

	  for(i=0;i<20;i++)
	    sprintf(&fpr[i*2],"%02X",fingerprint[i]);
	}
    }

  return fpr;
}

void
output_fingerprint(struct packet *packet,size_t public_len)
{
  if(packet->buf[0]==3)
    {
      
    }
  else if(packet->buf[0]==4)
    {
      SHA1Context sha;
      unsigned char head[3],fingerprint[20];

      if(SHA1Reset(&sha))
	abort();

      head[0]=0x99;
      head[1]=public_len>>8;
      head[2]=public_len&0xFF;

      SHA1Input(&sha,head,3);
      SHA1Input(&sha,packet->buf,public_len);
      SHA1Result(&sha,fingerprint);

      output(fingerprint,20);
    }
}


#define MPI_LENGTH(_start) (((((_start)[0]<<8 | (_start)[1]) + 7) / 8) + 2)

ssize_t
extract_secrets(struct packet *packet)
{
  ssize_t offset=0;

  if(packet->len==0)
    return -1;

  /* Secret keys consist of a public key with some secret material
     stuck on the end.  To get to the secrets, we have to skip the
     public stuff. */

  if(packet->buf[0]==3)
    {
      /*
	Jump 7 bytes in.  That gets us past 1 byte of version, 4 bytes
	of timestamp, and 2 bytes of expiration.
      */

      offset=7;
    }
  else if(packet->buf[0]==4)
    {
      /* Jump 5 bytes in.  That gets us past 1 byte of version, and 4
	 bytes of timestamp. */

      offset=5;
    }
  else
    return -1;

  if(packet->len<=offset)
    return -1;

  switch(packet->buf[offset++])
    {
    case 1: /* RSA */
      /* Skip 2 MPIs */
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      break;

    case 16: /* Elgamal */
      /* Skip 3 MPIs */
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      break;

    case 17: /* DSA */
      /* Skip 4 MPIs */
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      offset+=MPI_LENGTH(&packet->buf[offset]);
      if(packet->len<=offset)
	return -1;
      break;

    default:
      /* What algorithm? */
      fprintf(stderr,"Unable to parse algorithm %u\n",packet->buf[offset-1]);
      return -1;
    }

  return offset;
}

void
print_packet(struct packet *packet,ssize_t offset)
{
  ssize_t i;
  size_t line=0;
  size_t checksum=0;

  for(i=0;i+offset<packet->len;i++)
    {
      if(i%20==0)
	{
	  if(line)
	    printf("%04X",checksum);
	  printf("\n%2u:",++line);
	  checksum=0;
	}

      printf(" %02X",packet->buf[i+offset]);
      checksum+=packet->buf[i+offset];
    }

  printf("\n");
}
