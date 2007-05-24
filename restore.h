/* $Id$ */

#ifndef _RESTORE_H_
#define _RESTORE_H_

int restore(FILE *pubring,const char *secretname,
	    enum data_type input_type,const char *outname);

#endif /* !_RESTORE_H_ */

