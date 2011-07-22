/*
 * tcpforwarder
 *
 * Copyright (C) 2002-2005 by LIU Xin <smilerliu@gmail.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define VERSION "0.6.4.1"

#define LISTEN_QSIZE 5
#define DATA_BUFSIZE 4096
#define TMPSTRSIZE 4096
#define FILENAMESTRSIZE 4096

#define FILTER_ALLOW 1
#define FILTER_DENY 2

typedef union {
    struct sockaddr_in a4;
    struct sockaddr_in6 a6;
} NETADDR;

typedef struct tagFILTER {
    uint8_t data[sizeof(struct in6_addr)];
    int af, plen, action;
    struct tagFILTER *next;
} FILTER;

void usage();
void do_log(char *);
void err_msg(char *);
void main_sighndlr(int);
void chld_sighndlr(int);
void chld_atexit();
int make_filters();
int pass_filters();

char logfilename[FILENAMESTRSIZE], filterfilename[FILENAMESTRSIZE];
NETADDR raddr;
int raddrlen, clinum, maxclinum;
struct timeval whenclicome;
pid_t serverid;
FILTER *flist;

void
usage()
{
    printf("\nTCPForwarder Version %s\n", VERSION);
    printf("\nUsage:\n");
    printf("  tcpforwarder [ options ]");
    printf(" <localproto> <localaddr> <localport>");
    printf(" <svrproto> <svraddr> <svrport>\n");
    printf("\nOptions:\n");
    printf("  -o <logfile>\n  -m <maxclinum>\n  -l <filterfile>\n");
    printf("\n<localproto> could be \"ipv4\", \"ipv6\" or \"any\".\n");
    printf("<svrproto> could be \"ipv4\" or \"ipv6\".\n\n");
    exit(-1);
}

void
do_log(char *msg)
{
    FILE *fp;
    struct timeval tv;
    struct tm *ptm;

    if(logfilename[0]=='\0')
        return;
    memset(&tv, 0, sizeof(tv));
    gettimeofday(&tv, NULL);
    ptm=localtime(&tv.tv_sec);
    if((fp=fopen(logfilename, "a"))==NULL)
        return;
    flock(fileno(fp), LOCK_EX);
    if(fseek(fp, 0, SEEK_END)==0)
        fprintf(fp, "%d-%d-%d %d:%d:%d.%ld [%u] -- %s\n",
                ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday,
                ptm->tm_hour, ptm->tm_min, ptm->tm_sec, tv.tv_usec,
                serverid, msg);
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
}

void
err_msg(char *msg)
{
    printf("\nError: %s\n\n", msg);
}

void
main_sighndlr(int signo)
{
    int num;
    FILTER *p;
    char buf[TMPSTRSIZE];

    if(signo==SIGCHLD)
    {
        while(waitpid(-1, NULL, WNOHANG)>0)
            if(clinum>0)
                clinum--;
    }
    else if(signo==SIGTERM)
    {
        do_log("service terminated");
        kill(0, SIGTERM);
        exit(0);
    }
    else if(signo==SIGHUP)
    {
        while(flist!=NULL)
        {
            p=flist->next;
            free(flist);
            flist=p;
        }
        if(filterfilename[0]!='\0')
        {
            if((num=make_filters())>=0)
            {
                snprintf(buf, sizeof(buf),
                         "filters reconstructed: %d filters present", num);
                do_log(buf);
            }
            else
            {
                do_log("ERROR: bad filters");
                exit(-1);
            }
        }
    }
}

void
chld_sighndlr(int signo)
{
    if(signo==SIGTERM)
        exit(0);
}

void
chld_atexit()
{
    char sbuf[TMPSTRSIZE], sbuf2[TMPSTRSIZE], sbuf3[TMPSTRSIZE];
    struct timeval tv;

    gettimeofday(&tv, NULL);
    if(getnameinfo((struct sockaddr *)&raddr, raddrlen,
                   sbuf2, sizeof(sbuf2), sbuf3, sizeof(sbuf3),
                   NI_NUMERICHOST | NI_NUMERICSERV)!=0)
        snprintf(sbuf, sizeof(sbuf), "connection from some host terminated");
    else
        snprintf(sbuf, sizeof(sbuf), "connection from %s.%s terminated",
                 sbuf2, sbuf3);
    snprintf(sbuf2, sizeof(sbuf2), "%s ( %lds )",
             sbuf, tv.tv_sec-whenclicome.tv_sec);
    do_log(sbuf2);
}

int
make_filters()
{
    FILE *fp;
    char buf[TMPSTRSIZE], sbuf1[TMPSTRSIZE], sbuf2[TMPSTRSIZE], *pch;
    FILTER fhead, *p;
    int num;
    struct addrinfo *pai, *pai2, aihints;
    struct sockaddr_in *pa4;
    struct sockaddr_in6 *pa6;

    if((fp=fopen(filterfilename, "r"))==NULL)
        return -1;

    num=0;
    p=&fhead;
    p->next=NULL;
    while(fgets(buf, sizeof(buf), fp)!=NULL)
    {
        if(buf[0]=='#' || buf[0]=='\n')
            continue;
        if(sscanf(buf, "%s %s", sbuf1, sbuf2)!=2)
            goto on_error;
        if((p->next=malloc(sizeof(FILTER)))==NULL)
            goto on_error;
        p=p->next;
        p->next=NULL;
        if(strcasecmp(sbuf1, "allow")==0)
            p->action=FILTER_ALLOW;
        else if(strcasecmp(sbuf1, "deny")==0)
            p->action=FILTER_DENY;
        else
            goto on_error;
        if(strcasecmp(sbuf2, "all")==0)
        {
            p->plen=-1;
            num++;
            continue;
        }
        if((pch=strchr(sbuf2, '/'))!=NULL)
        {
            *(pch++)='\0';
            p->plen=strtoul(pch, &pch, 10);
            if(*pch!='\0')
                goto on_error;
        }
        else
            p->plen=-1;
        memset(&aihints, 0, sizeof(aihints));
        aihints.ai_flags=AI_NUMERICHOST;
        if(getaddrinfo(sbuf2, NULL, &aihints, &pai)!=0)
            goto on_error;
        for(pai2=pai; pai2!=NULL; pai2=pai2->ai_next)
            if(pai2->ai_family==AF_INET)
            {
                p->af=AF_INET;
                pa4=(struct sockaddr_in *)(pai2->ai_addr);
                pch=(char *)&(pa4->sin_addr);
                memcpy(p->data, pch, sizeof(struct in_addr));
                if(p->plen>32)
                {
                    freeaddrinfo(pai);
                    goto on_error;
                }
                else if(p->plen<0)
                    p->plen=32;
                break;
            }
            else if(pai2->ai_family==AF_INET6)
            {
                p->af=AF_INET6;
                pa6=(struct sockaddr_in6 *)(pai2->ai_addr);
                pch=(char *)&(pa6->sin6_addr);
                memcpy(p->data, pch, sizeof(struct in6_addr));
                if(p->plen>128)
                {
                    freeaddrinfo(pai);
                    goto on_error;
                }
                else if(p->plen<0)
                    p->plen=128;
                break;
            }
        if(pai2==NULL)
        {
            freeaddrinfo(pai);
            goto on_error;
        }
        num++;
        freeaddrinfo(pai);
    }

    flist=fhead.next;
    return num;

on_error:
    fclose(fp);
    p=fhead.next;
    while(p!=NULL)
    {
        fhead.next=p->next;
        free(p);
        p=fhead.next;
    }
    return -1;
}

int
pass_filters()
{
    FILTER *p;
    uint8_t *praddr;
    int af, match, n, i;

    af=((struct sockaddr *)&raddr)->sa_family;
    if(af==AF_INET)
        praddr=(uint8_t *)&(raddr.a4.sin_addr);
    else if(af==AF_INET6)
        praddr=(uint8_t *)&(raddr.a6.sin6_addr);
    else
        return -1;
    
    for(p=flist; p!=NULL; p=p->next)
    {
        if(p->plen==-1)
        {
            if(p->action==FILTER_ALLOW)
                return 0;
            else
                return -1;
        }
        if(p->af!=af)
            continue;
        match=1;
        for(i=0; i<p->plen/8; i++)
            if(p->data[i]!=praddr[i])
            {
                match=0;
                break;
            }
        if(match==0)
            continue;
        n=p->plen/8;
        i=p->plen%8;
        if(i>0 && (p->data[n]>>(8-i))!=(praddr[n]>>(8-i)))
            match=0;
        if(match==0)
            continue;
        if(p->action==FILTER_ALLOW)
            return 0;
        else
            return -1;
    }

    return -1;
}

int
main(int argc, char **argv)
{
    int localfd, clifd, svrfd, af, n, r, i;
    struct addrinfo aihints, *aipool[2], *plai, *psai;
    struct sockaddr_in v4a;
    struct sigaction act;
    FILE *fp;
    pid_t pid;
    fd_set fdset;
    char buf[DATA_BUFSIZE], *pchar;
    char sbuf[TMPSTRSIZE], sbuf2[TMPSTRSIZE], sbuf3[TMPSTRSIZE];

    serverid=getpid();
    memset(logfilename, 0, sizeof(logfilename));
    memset(filterfilename, 0, sizeof(filterfilename));
    maxclinum=0;
    opterr=0;
    while((r=getopt(argc, argv, "o:m:l:"))>0)
        switch(r)
        {
            case 'o':
                if(optarg[0]=='/')
                    n=0;
                else
                {
                    if(getcwd(logfilename, sizeof(logfilename))==NULL)
                    {
                        err_msg("getcwd");
                        return -1;
                    }
                    n=strlen(logfilename);
                    snprintf(logfilename+n, sizeof(logfilename)-n, "/");
                    n++;
                }
                snprintf(logfilename+n, sizeof(logfilename)-n, "%s", optarg);
                fp=NULL;
                if((fp=fopen(logfilename, "a"))==NULL)
                {
                    err_msg("<logfile>");
                    return -1;
                }
                if(fp!=NULL)
                    fclose(fp);
                break;
            case 'm':
                maxclinum=strtoul(optarg, &pchar, 10);
                if(*pchar!='\0')
                {
                    err_msg("<maxclinum>");
                    return -1;
                }
                break;
            case 'l':
                if(optarg[0]=='/')
                    n=0;
                else
                {
                    if(getcwd(filterfilename, sizeof(filterfilename))==NULL)
                    {
                        err_msg("getcwd");
                        return -1;
                    }
                    n=strlen(filterfilename);
                    snprintf(filterfilename+n, sizeof(filterfilename)-n, "/");
                    n++;
                }
                snprintf(filterfilename+n, sizeof(filterfilename)-n,
                         "%s", optarg);
                fp=NULL;
                if((fp=fopen(filterfilename, "r"))==NULL)
                {
                    err_msg("<filterfile>");
                    return -1;
                }
                if(fp!=NULL)
                    fclose(fp);
                break;
            default:
                usage();
        }
    argc-=optind;
    argv+=optind;

    if(argc<6)
        usage();

    memset(&aipool, 0, sizeof(aipool));

    memset(&aihints, 0, sizeof(aihints));
    if(strcasecmp(argv[0], "ipv4")==0)
        af=AF_INET;
    else if(strcasecmp(argv[0], "ipv6")==0)
        af=AF_INET6;
    else if(strcasecmp(argv[0], "any")==0)
        af=AF_UNSPEC;
    else
    {
        err_msg("<localproto>");
        return -1;
    }
    aihints.ai_family=af;
    aihints.ai_socktype=SOCK_STREAM;
    aihints.ai_flags=AI_PASSIVE;
    if(strcasecmp(argv[1], "any")==0)
        pchar=NULL;
    else
        pchar=argv[1];
    if(getaddrinfo(pchar, argv[2], &aihints, &aipool[0])!=0)
    {
        err_msg("<localaddr> or <localport>");
        return -1;
    }
    for(plai=aipool[0]; plai!=NULL; plai=plai->ai_next)
        if(plai->ai_family==AF_INET || plai->ai_family==AF_INET6)
        {
            if((localfd=socket(plai->ai_family,
                               plai->ai_socktype,
                               plai->ai_protocol))<0)
                continue;
            else
            {
                close(localfd);
                break;
            }
        }
    if(plai==NULL)
    {
        err_msg("<localaddr> or <localport>: no available addr");
        return -1;
    }

    memset(&aihints, 0, sizeof(aihints));
    if(strcasecmp(argv[3], "ipv4")==0)
        aihints.ai_family=AF_INET;
    else if(strcasecmp(argv[3], "ipv6")==0)
        aihints.ai_family=AF_INET6;
    else if(strcasecmp(argv[3], "any")==0)
        aihints.ai_family=AF_UNSPEC;
    else
    {
        err_msg("<svrproto>");
        return -1;
    }
    aihints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(argv[4], argv[5], &aihints, &aipool[1])!=0)
    {
        err_msg("<svraddr> or <svrport>");
        return -1;
    }
    for(psai=aipool[1]; psai!=NULL; psai=psai->ai_next)
        if(psai->ai_family==AF_INET || psai->ai_family==AF_INET6)
            break;
    if(psai==NULL)
    {
        err_msg("<svraddr> or <svrport>: no available addr");
        return -1;
    }

    do_log("");
    do_log("tcpforwarder started");
    flist=NULL;
    if(filterfilename[0]!='\0')
    {
        if((n=make_filters())>=0)
        {
            snprintf(sbuf, sizeof(sbuf),
                     "filters constructed: %d filters present", n);
            do_log(sbuf);
        }
        else
        {
            do_log("ERROR: bad filters");
            return -1;
        }
    }
    if(daemon(0, 0)<0)
    {
        do_log("ERROR: daemonization failed");
        return -1;
    }
    memset(&act, 0, sizeof(act));
    act.sa_handler=main_sighndlr;
    if(sigaction(SIGCHLD, &act, NULL)<0
       || sigaction(SIGTERM, &act, NULL)<0
       || sigaction(SIGHUP, &act, NULL)<0)
    {
        do_log("ERROR: signal handler setup for main process failed");
        return -1;
    }

    if((localfd=socket(plai->ai_family,
                       plai->ai_socktype,
                       plai->ai_protocol))<0)
    
    {
        do_log("ERROR: service socket creation failed");
        return -1;
    }
    i=1;
    if(setsockopt(localfd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i))<0)
    {
        do_log("ERROR: setsockopt() for service socket failed");
        return -1;
    }
    if(bind(localfd, plai->ai_addr, plai->ai_addrlen)<0)
    {
        do_log("ERROR: bind() for service socket failed");
        return -1;
    }
    if(listen(localfd, LISTEN_QSIZE)<0)
    {
        do_log("ERROR: listen() for service socket failed");
        return -1;
    }

    if(getnameinfo(plai->ai_addr, plai->ai_addrlen,
                   sbuf2, sizeof(sbuf2), sbuf3, sizeof(sbuf3),
                   NI_NUMERICHOST | NI_NUMERICSERV)!=0)
        snprintf(sbuf, sizeof(sbuf), "service is running");
    else
        snprintf(sbuf, sizeof(sbuf), "service is running at %s.%s",
                 sbuf2, sbuf3 );
    do_log(sbuf);

    clinum=0;
    while(1)
    {
        raddrlen=sizeof(raddr);
        if((clifd=accept(localfd, (struct sockaddr *)&raddr, (socklen_t *)&raddrlen))<0)
        {
            if(errno==EINTR)
                continue;
            else
            {
                do_log("ERROR: accept() on service socket failed");
                return -1;
            }
        }
        r=((struct sockaddr *)&raddr)->sa_family;
        if(r==AF_INET6 && af==AF_UNSPEC
           && IN6_IS_ADDR_V4MAPPED(&raddr.a6.sin6_addr))
        {
            memset(&v4a, 0, sizeof(v4a));
            v4a.sin_family=AF_INET;
            v4a.sin_port=raddr.a6.sin6_port;
            pchar=(char *)&(raddr.a6.sin6_addr);
            pchar+=12;
            v4a.sin_addr.s_addr=*((uint32_t *)pchar);
            raddr.a4=v4a;
            raddrlen=sizeof(v4a);
        }
        if(getnameinfo((struct sockaddr *)&raddr, raddrlen,
                       sbuf2, sizeof(sbuf2), sbuf3, sizeof(sbuf3),
                       NI_NUMERICHOST | NI_NUMERICSERV)!=0)
            snprintf(sbuf, sizeof(sbuf), "connection from some host");
        else
            snprintf(sbuf, sizeof(sbuf), "connection from %s.%s",
                     sbuf2, sbuf3);
        if(maxclinum>0 && clinum>=maxclinum)
        {
            snprintf(sbuf2, sizeof(sbuf2),
                     "%s refused: client number limit reached", sbuf);
            do_log(sbuf2);
            close(clifd);
            continue;
        }
        else if(flist!=NULL && pass_filters()<0)
        {
            snprintf(sbuf2, sizeof(sbuf2),
                     "%s refused: denied by filters", sbuf);
            do_log(sbuf2);
            close(clifd);
            continue;
        }
        else
            do_log(sbuf);

        if((pid=fork())<0)
            return -1;
        else if(pid>0)
        {
            clinum++;
            close(clifd);
            continue;
        }

        gettimeofday(&whenclicome, NULL);
        memset(&act, 0, sizeof(act));
        act.sa_handler=SIG_DFL;
        if(sigaction(SIGCHLD, &act, NULL)<0 || sigaction(SIGHUP, &act, NULL)<0)
            return -1;
        memset(&act, 0, sizeof(act));
        act.sa_handler=chld_sighndlr;
        if(sigaction(SIGTERM, &act, NULL)<0)
            return -1;
        atexit(chld_atexit);
        close(localfd);
        if((svrfd=socket(psai->ai_family,
                         psai->ai_socktype,
                         psai->ai_protocol))<0)
        {
            snprintf(sbuf, sizeof(sbuf),
                     "Child[%u]: socket creation failed", getpid());
            do_log(sbuf);
            return -1;
        }
        if(connect(svrfd, psai->ai_addr, psai->ai_addrlen)<0)
        {
            snprintf(sbuf, sizeof(sbuf),
                     "Child[%u]: Unable to connect to server", getpid());
            do_log(sbuf);
            return -1;
        }

        while(1)
        {
            FD_ZERO(&fdset);
            FD_SET(clifd, &fdset);
            FD_SET(svrfd, &fdset);
            n=(clifd>svrfd?clifd:svrfd)+1;
            if((r=select(n, &fdset, NULL, NULL, NULL))<0)
            {
                if(errno==EINTR)
                    continue;
                else
                {
                    snprintf(sbuf, sizeof(sbuf),
                             "Child[%u]: select() failed", getpid());
                    do_log(sbuf);
                    return -1;
                }
            }
            if(FD_ISSET(clifd, &fdset))
            {
                if((n=read(clifd, buf, sizeof(buf)))<0)
                {
                    if(errno==EINTR)
                        continue;
                    else if(errno==EBADF)
                        break;
                    else
                    {
                        snprintf(sbuf, sizeof(sbuf),
                                 "Child[%u]: read from client failed",
                                 getpid());
                        do_log(sbuf);
                        return -1;
                    }
                }
                else if(n==0)
                    break;
                i=0;
                while(i<n)
                {
                    if((r=write(svrfd, buf+i, n-i))<0)
                    {
                        if(errno==EINTR)
                            continue;
                        else if(errno==EBADF)
                            break;
                        else
                        {
                            snprintf(sbuf, sizeof(sbuf),
                                     "Child[%u]: write to server failed",
                                     getpid());
                            do_log(sbuf);
                            return -1;
                        }
                    }
                    i+=r;
                }
                if(i<n)
                    break;
            }
            if(FD_ISSET(svrfd, &fdset))
            {
                if((n=read(svrfd, buf, sizeof(buf)))<0)
                {
                    if(errno==EINTR)
                        continue;
                    else if(errno==EBADF)
                        break;
                    else
                    {
                        snprintf(sbuf, sizeof(sbuf),
                                 "Child[%u]: read from server failed",
                                 getpid());
                        do_log(sbuf);
                        return -1;
                    }
                }
                else if(n==0)
                    break;
                i=0;
                while(i<n)
                {
                    if((r=write(clifd, buf+i, n-i))<0)
                    {
                        if(errno==EINTR)
                            continue;
                        else if(errno==EBADF)
                            break;
                        else
                        {
                            snprintf(sbuf, sizeof(sbuf),
                                     "Child[%u]: write to client failed",
                                     getpid());
                            do_log(sbuf);
                            return -1;
                        }
                    }
                    i+=r;
                }
                if(i<n)
                    break;
            }
        }
        return 0;
    }

    return -1;
}
