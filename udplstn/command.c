#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "udplstn.h"

char optstrg[]="vchp:l:r:d:a:m:";


extern void usage(char *);

/* v - verbose
 * c - command line
 * p - port
 * l - logfile
 * r - rootdir for and packets
 * a - alarmtime
 * m - Max packets number accepted, within alarmtime period
 */

extern unsigned char verbose;
extern unsigned short int port;
extern char *logfile;
extern char *packdir;
extern char **commandline;
extern unsigned int alrmtime;
extern unsigned int packsperalrm;

void parse_cmd (int argc, char **argv)
{
	int c;
	int done=0;

	/* set defaults first */
	alrmtime=ALRMTIME;
	packsperalrm=PACKSPERALRM;

	while ((c=getopt(argc, argv, optstrg)) != EOF) {
		switch(c) {
	case 'v' : verbose=1;
		   break;
	
	case 'c' : commandline=&argv[optind];
		   done=1;
		   break;
	case 'p' : port=atoi(optarg);
		   break;
	case 'l' : logfile=optarg;
		   break;
	case 'r' : packdir=optarg;
		   break;
	case 'a' : if(!isdigit(optarg[0])) usage(argv[0]);/* we are foolproof */
		   alrmtime=atoi(optarg);
		   break;
	case 'm' : if(!isdigit(optarg[0])) usage(argv[0]);/* we are foolproof */
		   packsperalrm=atoi(optarg);
		   break;
	case 'h' :
	case '?' : usage(argv[0]);
		   break;
	default:
		   usage(argv[0]);
		   break;
		} /* switch */
		if (done) break; /* we do not process anything after cmdline */
	}/* while */

	if(port==0) usage(argv[0]);
}


void show_config() {
char **foo;
	
printf("logfile:\t%s\n",logfile);
printf("packdir:\t%s\n",packdir);
printf("port:\t%i\n",port);
printf("Alarm time period:\t%i seconds\n",alrmtime);
if(!alrmtime) printf("Server will die when %i packets received\n",packsperalrm);
printf("Maximum packets logged per alarm time period:\t%i\n",packsperalrm);
if(!packsperalrm) 
	printf("Reverting to older behaviour\n\a"
        "This might be unsafe and vulneriable to several DoS attacks\n");

foo=commandline;
if (foo) {
	printf("command line:");
		
	while(*foo!=NULL) {
		printf(" %s",*foo);
		foo++;
	}
	printf("\n");
}/* if command line is present */
}
#ifdef HAVE_MAIN

int main(int argc, char **argv) {

	parse_cmd(argc,argv);
	return 0;
}

#endif
