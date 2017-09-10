#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#ifndef __USE_BSD
#define __USE_BSD
#endif
#define __FAVOR_BSD
#define	ip_csum	ip_sum
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include "config.h"

#ifdef BSD
#define FIX(n)	(n)
#else
#define FIX(n)	htons(n)
#endif

/* linux libc5 compatibility */
#if defined(__linux__) && (!defined(__GLIBC__) || (__GLIBC__ < 2))
#define	uh_sport		source
#define	uh_dport		dest
#define	uh_ulen			len
#define	ICMP_UNREACH_PORT	ICMP_PORT_UNREACH
#define	ICMP_UNREACH		ICMP_DEST_UNREACH
#define	ICMP_TIMXCEED		ICMP_TIME_EXCEEDED
#define	ICMP_TIMXCEED_INTRANS	ICMP_EXC_TTL
#endif

#define	IP_SIZE		(sizeof(struct ip))
#define	ICMP_SIZE	(sizeof(struct icmp2))
#define	UDP_SIZE	(sizeof(struct udphdr))
#define	SIZE_UNREACH	68
#define	SIZE_TEXCEED	56

/* Structures */
struct icmp2 {
   u_char icmp_type;		/* icmp type */
   u_char icmp_code;		/* type sub code */
   u_short icmp_cksum;		/* checksum */
   u_char unused[4];		/* not needed */
};

struct in_pack {
   struct ip ip;
   struct udphdr udp;
   u_char seq, ttl;
   struct timeval tv;
};

/* Prototypes */
u_short csum(u_short *, int);
u_long lookup(const char *);
void fake_reply(struct in_pack *t, int);
void handlepkt(u_char *, int);
int grab_sockets(int);

/* Global Vars */
int sndsck, fakecount;
char **fakehops;

u_short in_cksum(u_short *addr, int len)
{
   register int nleft = len;
   register u_short *w = addr;
   register u_short answer;
   register int sum = 0;

/*
 *  Our algorithm is simple, using a 32 bit accumulator (sum),
 *  we add sequential 16 bit words to it, and at the end, fold
 *  back all the carry bits from the top 16 bits into the lower
 *  16 bits.
 */
   while (nleft > 1)  {
      sum += *w++;
      nleft -= 2;
   }

   /* mop up an odd byte, if necessary */
   if (nleft == 1)
      sum += *(u_char *)w;

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
   sum += (sum >> 16);			/* add carry */
   answer = ~sum;			/* truncate to 16 bits */
   return (answer);
}

u_long lookup(const char *hostname)
{
   struct in_addr addr;
   struct hostent *hostent;

   if ((addr.s_addr = inet_addr(hostname)) == -1) {
      if (!(hostent = gethostbyname(hostname)))
         return (0);

      memcpy((char *)&addr.s_addr, hostent->h_addr, hostent->h_length);
   }

   return (addr.s_addr);
}

void fake_reply(struct in_pack *in_pkt, int hop)
{
   struct sockaddr_in dest;
   struct ip *ip1, *ip2;
   struct icmp2 *icmp;
   struct udphdr *udp;
   u_char outbuf[128];
   int pktsize;

   if (hop < (fakecount - 1))
   	pktsize = SIZE_TEXCEED;
   else
   	pktsize = SIZE_UNREACH;

   memset(outbuf, 0, pktsize);
   memset(&dest, 0, sizeof(struct sockaddr_in));

   ip1  = (struct ip *)(outbuf);
   icmp = (struct icmp2 *)(outbuf+IP_SIZE);
   ip2  = (struct ip *)(outbuf+IP_SIZE+ICMP_SIZE);
   udp  = (struct udphdr *)(outbuf+IP_SIZE+ICMP_SIZE+IP_SIZE);

   dest.sin_family		= AF_INET;
   dest.sin_addr.s_addr		= (u_long)in_pkt->ip.ip_src.s_addr;
   dest.sin_port		= 0;

   ip1->ip_src.s_addr		= (u_long)lookup(fakehops[hop]);
   ip1->ip_dst.s_addr		= (u_long)in_pkt->ip.ip_src.s_addr;
   ip1->ip_v			= 4;
   ip1->ip_hl			= 5;
   ip1->ip_tos			= 192;
   ip1->ip_len			= FIX(pktsize);
   ip1->ip_id			= in_pkt->ip.ip_id;
   ip1->ip_off			= 0;
   ip1->ip_p			= IPPROTO_ICMP;
   ip1->ip_ttl			= 255;

   memcpy(ip2, &in_pkt->ip, sizeof(struct ip));
   memcpy(udp, &in_pkt->udp, UDP_SIZE);

   if (hop < (fakecount - 1)) {
      icmp->icmp_type		= ICMP_TIMXCEED;
      icmp->icmp_code		= ICMP_TIMXCEED_INTRANS;
      udp->uh_ulen		= UDP_SIZE;
   } else {
#ifdef FINAL_HOP_LOOKS_LIKE_LINUX
      ip1->ip_ttl		= 64;
#endif
      icmp->icmp_type		= ICMP_UNREACH;
      icmp->icmp_code		= ICMP_UNREACH_PORT;
      udp->uh_ulen		= UDP_SIZE + 12;
   }

   ip2->ip_p			= IPPROTO_UDP;
   ip2->ip_hl			= 5;

   icmp->icmp_cksum		= in_cksum((u_short *)icmp, ICMP_SIZE);
   ip1->ip_sum			= in_cksum((u_short *)ip1, pktsize);

   sendto(sndsck, outbuf, pktsize, 0, (struct sockaddr *)&dest, sizeof(dest));
}

void handlepkt(u_char *inbuf, int len)
{
   struct in_pack *pkt;
   unsigned int sport, dport;

   pkt = (struct in_pack *)inbuf;
   sport = ntohs(pkt->udp.uh_sport);
   dport = ntohs(pkt->udp.uh_dport);

   if (dport < BASEPORT || dport > (BASEPORT+MAX_SOCK))
      return;

   printf("Traceroute from: %s", inet_ntoa(pkt->ip.ip_src));
   fflush(stdout);
   printf(" to %s (%d bytes) Hop: %d Probe: %d\n", inet_ntoa(pkt->ip.ip_dst),
   len, ((dport - 33435) / 3) + 1, (dport % 3) + 1);
   fflush(stdout);

   if ((pkt->ip.ip_ttl <= fakecount) && (fakecount != 0))
      fake_reply(pkt, pkt->ip.ip_ttl - 1);
}

int grab_sockets(int fakecount)
{
   struct sockaddr_in sin;
   int raw, s, i;

   memset(&sin, 0, sizeof(sin));
   sin.sin_family = AF_INET;
   sin.sin_addr.s_addr = INADDR_ANY;

   if ((raw = socket(AF_INET, SOCK_RAW, 0)) < 0) {
      perror("socket");
      if ((errno == EPERM) || (errno == EACCES))
         fprintf(stderr, "must run as root\n");
      exit(2);
   }

   if (fakecount) {
      if ((sndsck = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
         perror("socket");
         if ((errno == EPERM) || (errno == EACCES))
            fprintf(stderr, "must run as root\n");
         exit(2);
      }

      for(i=0;i<MAX_SOCK+1;i++) {
         if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            perror("socket");
            exit(1);
         }

         sin.sin_port = htons(BASEPORT+i);
         if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("bind");
            exit(1);
         }
      }
   }

/* Drop any euid or egid we might have and no longer need */
   setgid(getgid());
   setuid(getuid());

   return raw;
}

int main(int argc, char *argv[])
{
   u_char inbuf[128];
   int rawudp;

   fakecount = argc - 1;
   fakehops = argv + 1;

   rawudp = grab_sockets(fakecount);

   for(;;)
      handlepkt(inbuf, read(rawudp, (void *)inbuf, sizeof(inbuf)));

   return 0;
}
