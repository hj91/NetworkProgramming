#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

extern unsigned volatile int packcount;
extern unsigned char verbose;
extern unsigned int alrmtime;

void sigalrm(int sig) {
	packcount=0; /* every ALRMTIME we zero the counter */
	alarm(alrmtime);
	/* if the code dies right after first alarmtime, uncomment
	 * the line bellow
	signal(SIG_ALRM,sigalrm);
	 */
	
}

void ignore_packet(void) {
time_t t;
	if (verbose) {
	 time(&t);
	 printf("Packets overflow [%i] at:%s",packcount,asctime(localtime(&t)));
      }
/* if either alrmtime is 0 then there's no reason to remain (since we won't
 * log anything however*/
if (!alrmtime) {
	time(&t);
	printf("Abort on packets overflow [%i] at:%s",
			packcount,asctime(localtime(&t)));
	exit(1);
   }
}
