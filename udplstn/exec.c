#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "udplstn.h"


extern char **commandline;

void exec_cmd(SA *cltaddr,int len,char *buf,int packlen)
{
     char **foo;
     char ipbuf[IPSIZE+1];
     char prtbuf[PRTSIZE+1];
     int execstat;

     foo=commandline;

#ifdef DEBUG
     printf("trying to fork:");
#endif     
	snprintf(ipbuf,IPSIZE,"%s",inet_ntoa(cltaddr->sin_addr));
	snprintf(prtbuf,PRTSIZE,"%i",ntohs(cltaddr->sin_port));
#ifdef DEBUG
	printf("IP:\t%s\nPORT:\t%s\n",ipbuf,prtbuf);
#endif
     
     if (foo==NULL) return; /* well, that's a double checking */
     /* ajusting parameters */
     while (* foo!=NULL) {
	     if (!strcasecmp(*foo,"IPADDR")) *foo=ipbuf;
	     if (!strcasecmp(*foo,"PORT")) *foo=prtbuf;
#ifdef DEBUG
	     printf("%s ",*foo);
#endif	     
	     foo++;
     }
#ifdef DEBUG
	     printf("\n");
#endif	     
 
	if(fork()) return; /* parent returns immediately */
	/* 
	 * we do things with security in mind :-)
	 *  so you will need to point the path exactly :-)
	 *  if you want to fix this
	 *  uncomment the line bellow and comment
	 *  the other one.
	 */
	/*execstat=execv(commandline[0],commandline);*/
	execstat=execvp(commandline[0],commandline);
#ifdef DEBUG
	printf("Fork failed:%X\n",execstat);
#endif	
	exit(execstat);/* if only exec failed */
}

