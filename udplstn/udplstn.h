/* common stuff */

#define LOGFILE "listen.log"
#define PACK_PREFIX "pack"
#define PACK_DIR "."
#define LOGDIR "."
#define BUFSIZE 256
#define F_MODE 00600
/* size of buffer for IP address 255.255.255.255 4*3+3=15 */
#define IPSIZE 15
/* size of buffer for PORT (ascii) 65535 -> 5 */
#define PRTSIZE 5

/* the time, when alarm signal is called */
#ifndef ALRMTIME
#define ALRMTIME 5
#endif

/* the maximum number of packets, which will be stored
 * within a single ALRMTIME period. the packets, which overcome. Are ignored
 */
#ifndef PACKSPERALRM
#define PACKSPERALRM 10
#endif

typedef struct sockaddr_in SA;
