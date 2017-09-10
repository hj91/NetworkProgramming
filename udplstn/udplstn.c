#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "udplstn.h"

static unsigned int seq=0;

/* default values */
 char *logfile=LOGFILE;
 char *packdir=PACK_DIR;
 char **commandline=NULL;
 unsigned char verbose=0;
unsigned short int port=0;
unsigned volatile int packcount=0;
unsigned int alrmtime=0;
unsigned int packsperalrm=0;

extern void parse_cmd (int, char **);
extern void exec_cmd(SA *,int,char *,int);
void savepack(SA *,int,char *,int);

extern void show_config(void);
extern void sigalrm(int);
extern void ignore_packet(void);

void usage(char *myname)
{
	fprintf(stderr,"Usage: %s -p portnum [-v] [-l logfile] [-r rootdir for"
"packs] [-a alarmtime] [-m packets_per_alarm_period ] [-c command [args]] \n"
"NOTE: among command line arguments you may use following keywords:\n"
"\tIPADDR\tto put the IP address where packet is originated\n"
"\tPORT\tto put the port number, which packet came from\n" ,myname); 
		exit(1);
}

int main(int argc, char **argv)
{
 char buf[BUFSIZE+1];
 time_t t;
 int sockfd,len,packlen,waitst;
/* unsigned int flags; */
 struct sockaddr_in srvaddr,cltaddr;
 
 parse_cmd(argc,argv);
 
 if (verbose) show_config();
 
#ifndef DEBUG
  if (access(logfile,W_OK) && !access(logfile,F_OK))
   	{ fprintf(stderr,"Can not write to logfile:%s\n ",logfile);
		return -1;
		}
  if (access(logfile,F_OK)) 
	  fprintf(stderr,"Warning: logfile does not exist.\n");
  
		  
#endif
  if(access(packdir,W_OK)) {
   	fprintf(stderr,"packets saving directory %s is not writable\n"
			,packdir);
	return -1;
	}

#ifndef DEBUG
if (fork()) return 0; /* father dies. child goes background */
	 close(0);
	 close(1);
	 close(2);
	 setsid();
	 umask(0);
	 open(logfile,O_WRONLY|O_CREAT|O_APPEND,F_MODE);
	 dup(0);
	 dup(0); /* all logs and stdout is the same */
#endif
	 time(&t);
	 /* point the time when started */
         printf("-=%s",asctime(localtime(&t)));
	 fflush(stdout);
	 /* set signal handler for alarm, until packsalrm=0 specified.
	  * (in this case we will  log all the packets with no limits)
	  */
	 if(packsperalrm) {
		 signal(SIGALRM,sigalrm);
		 /* we don't check alrmtime==0, so we could have 
		  * another feature: if specified alrmtime is 0,
		  * then packsperalrm value shows the maximum packets
		  * we could have before quiting.*/
		 alarm(alrmtime);
	 }
	 if((sockfd = socket(AF_INET,SOCK_DGRAM,0))==-1) {
		 perror("socket:");
		 return 1;
	 }
	 bzero(&srvaddr,sizeof(srvaddr));
	 srvaddr.sin_family=AF_INET;
	 srvaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	 srvaddr.sin_port=htons(port);

	 if(bind(sockfd,(struct sockaddr *) &srvaddr,sizeof(srvaddr))) {
		perror("bind:");
		fprintf(stderr,"port was: %i\n",port);
		fflush(stderr);
		return 1;
	 }

	 /* start loggin' packets here */
	 for( ; ; ) {
		 len=sizeof(cltaddr);
		 if((packlen=recvfrom(sockfd,buf,BUFSIZE,0,
			(struct sockaddr *)&cltaddr,&len))==-1) {
			 			perror("recvfrom:");
						fflush(stderr);
						return 0;
		 }
		 packcount++;
		 /* if we counted  packets per alarmtime
		  * overrun, then we shall call ignore_packet.
		  * (will not log it, will not save it (only leave a mark)-
		  * -- so it should be safe enough againist most DoS */
		 if (packsperalrm && packcount>packsperalrm) {
			 ignore_packet();
			 /* leaving mark should be save enough */
			 printf("[!] from:\t%s:%i\n",
			inet_ntoa(cltaddr.sin_addr), ntohs(cltaddr.sin_port));
			 continue;
		 }
#ifdef PONG
		 sendto(sockfd,buf,packlen,0,(struct sockaddr *)&cltaddr,len);/*pong*/
#endif
		 savepack(&cltaddr,len,buf,packlen);
	if (commandline) { 
		exec_cmd(&cltaddr,len,buf,packlen);
		waitpid(-1,&waitst,0);
	}
		/* note to make things going faster you may make:
		 * while(waitpid(-1,&waitst,WNOHANG)!=-1);
		 *
		 * this will make your code working faster,
		 *   but may cause some DoS attacks.
		 */

	 }/* never reached */
	 return 0;
}


void savepack(SA *cltaddr,int addrlen,char *buf,int buflen) {
	char packfile[BUFSIZE+1];
	time_t t;
	int fd;

	time(&t);
	printf("[0x%08X]UDP from %s:%i\t[size:0x%04X]\t%s",seq,
		inet_ntoa(cltaddr->sin_addr),
		ntohs(cltaddr->sin_port),buflen,asctime(localtime(&t)));
	seq++;/* we just need to count sequences somehow */
	fflush(stdout);
	snprintf(packfile,BUFSIZE,"%s/%s.%s.%i.%i.0x%08X",packdir,PACK_PREFIX,
			inet_ntoa(cltaddr->sin_addr),ntohs(cltaddr->sin_port),
			(unsigned int)t,seq);
	if(!access(packfile,F_OK)) {
		printf("file %s exist.(no overwrite)\n",packfile);
		fflush(stdout);
		return;/* we dont want to overwrite existing file */
	}
	if((fd=open(packfile,O_WRONLY|O_CREAT,F_MODE))==-1) {
		perror("can not open pack.file:");
		fflush(stderr);
		return;
	}
	if (write(fd,buf,buflen)!=buflen) {
		perror("write error:");
		fflush(stderr);
	}
	close(fd);
	return;
}
	
