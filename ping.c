#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>

#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

//#define DEBUG
#define DELAY 1000
#define TIME_TO_WAIT 3000
#define TTL 64
#define NO_RECORD_ROUTE 0
#define NO_HELP 0
#define HELP 1
#define RECORD_ROUTE 1
#define MAX_SIZE 65535

int sock;
char *buf;
char *packet;

struct opts_t{
    int delay; //millisec
    int time_to_wait; //millisec;
    int record_route;
    int ttl;
    int help;
    int count;
    int sent;
    int rcvd;
    int quiet;
    int freed;
    unsigned short int id;
    char *target;
    char *source;
};

struct rroute_t{
    char nop;
    char type;
    char length;
    char pointer;
    unsigned int addr[9];
};

static const struct option opts[] = {
    { "delay", required_argument, NULL, 'D'},
    { "quiet", no_argument, NULL, 'q' },
    { "destination", required_argument, NULL, 'd' },
    { "time-to-wait", required_argument, NULL, 'w' },
    { "record-route", no_argument, NULL, 'R' },
    { "ttl", required_argument, NULL, 't' },
    { "help", no_argument, NULL, 'h' },
    { "count", required_argument, NULL, 'c' },
    { NULL, no_argument, NULL, 0 }
};

static const char *optstr = "d:D:w:Rt:hc:q";

struct opts_t glob_opts;

void mem_free();

void wait(int t){
    t *= 1000;
    struct timeval tmp;
    tmp.tv_sec = t / 1000000;
    tmp.tv_usec = t % 1000000;
    select(0,NULL,NULL,NULL,&tmp);
}

void show_help(){
    printf(
"Usage: ping [-c count] [-w time] [-q] [-D delay]\n"
"            [-h] [-R] [-t] -d target\n"
"Options:\n"
"   -c count --count count          Send $count probes\n"
"   -w time --time-to-wait time     Wait $time milliseconds for reply\n"
"   -q --quiet                      Print only statistics string\n"
"   -D time --delay time            Wait $delay millisecond for sending next probe\n"
"   -h --help                       Show this help and exit\n"
"   -R --record-route               Set the ip's record-route option\n"
"   -t num --ttl num                Set ttl to $num\n"
"   -d target --destination target  Set target to ping\n");
}

void error(char *str){
    fprintf(stderr,"ERROR: %s\n",str);
    mem_free();
    exit(1);
}

void p_error(char *str){
    perror(str);
    mem_free();
    exit(1);
}

void warn(char *str){
    fprintf(stderr,"WARNING: %s\n",str);
}

void check_args(){
    if (glob_opts.delay < 1){
        error("Delay must be greater than 1.");
    }
    if (glob_opts.time_to_wait < 0){
        error("Negative time-to-wait is not allowed."); 
    }
    if (glob_opts.ttl < 0){
        error("Negative ttl is not allowed.");
    }
    if (glob_opts.ttl > 255){
        error("ttl is too big.");
    }
    if (glob_opts.count < -1){
        error("Negative count is not allowed.");
    }
}

int parse_msg(struct timeval *t_rcvd){
    int rc = 0;
// buf - is that thing, we must work on!
    struct iphdr *ip;
    struct icmphdr *icmp;
    char *ip_opt;
    char *data;
    int offset;
// Firstly - ip header
    ip = (struct iphdr *)buf;
// Any ip-options are here
    ip_opt = (buf + sizeof(struct iphdr));
// Now we'll find icmp header
    offset = ip->ihl * 4;
    icmp = (struct icmphdr *)(buf + offset);
    switch(icmp->type){
        case ICMP_ECHOREPLY :
            {
                if (icmp->un.echo.id == glob_opts.id){
                    rc = 1;
                    glob_opts.rcvd += 1;
                    //ok, it is time to calculate round-trip time
                    if (glob_opts.quiet == 0){
                        data = ((char *)icmp) + sizeof(struct icmphdr);
                        struct sockaddr_in tmp;
                        tmp.sin_addr.s_addr = ip->saddr;
                        double t;
                        struct timeval *t_msg;
                        t = t_rcvd->tv_sec*1000000 + t_rcvd->tv_usec;
                        t_msg = (struct timeval *)data;
                        t -= (t_msg->tv_sec*1000000 + t_msg->tv_usec);
                        t /= 1000;
                        printf("Echo reply from: %s seq=%d ttl=%d time=%.2f ms\n",inet_ntoa(tmp.sin_addr),icmp->un.echo.sequence, ip->ttl, t);
                        // If there was some useful options for us.
                        if (ip->ihl > 5){
                            int opt_size = (ip->ihl - 5) * 4;
                            int i = 0;
                            // Skip all nops
                            while((*ip_opt == 1) && (i < opt_size)){
                                ++ip_opt;
                                ++i;
                            }
                            // Record Route option
                            if (*ip_opt == 7){
                                printf("RR:");
                                // Let's find the pointer
                                int pointer = 0;
                                pointer = (unsigned char)*(ip_opt + 2);
                                int addr_size = (pointer - 8)/4;
                                int *addr_data = (int *)(ip_opt + 3);
                                struct sockaddr_in tmp;
                                int j = 0;
                                while(j < addr_size){
                                    tmp.sin_addr.s_addr = *addr_data;
                                    printf("\t%s\n",inet_ntoa(tmp.sin_addr));
                                    ++j;
                                    ++addr_data;
                                }
                            }
                        }
                    }
                    rc = 1;
                }
            }
        break;
        case ICMP_TIME_EXCEEDED :
            {
                char *tmp_ptr;
                struct sockaddr_in tmp_addr;
                tmp_addr.sin_addr.s_addr = ip->saddr;
                //Here is our original datagram
                tmp_ptr = (char *)icmp + sizeof(struct icmphdr);
                ip = (struct iphdr *)tmp_ptr;
                icmp = (struct icmphdr *)(tmp_ptr + ip->ihl * 4);
                if (icmp->un.echo.id == glob_opts.id){
                    printf("TTL exceeded from: %s\n",inet_ntoa(tmp_addr.sin_addr));
                }
            }
        break;
        case ICMP_DEST_UNREACH :
            {
                char *tmp_ptr;
                struct sockaddr_in tmp_addr;
                tmp_addr.sin_addr.s_addr = ip->saddr;
                int code = icmp->code;
                //Here is our original datagram
                tmp_ptr = (char *)icmp + sizeof(struct icmphdr);
                ip = (struct iphdr *)tmp_ptr;
                icmp = (struct icmphdr *)(tmp_ptr + ip->ihl * 4);
                if (icmp->un.echo.id == glob_opts.id){
                    printf("Destination unreachable: ");
                    switch (code){
                        case ICMP_NET_UNREACH :
                            printf("Network Unreachable");
                        break; 
                        case ICMP_HOST_UNREACH :
                            printf("Host Unreachable");
                        break; 
                        case ICMP_FRAG_NEEDED :
                            printf("Fragmentation Needed/DF set");
                        break;
                        case ICMP_SR_FAILED :
                            printf("Source Route failed");
                        break;
                        default:
                            printf("err: Unsupported icmp code");
                        break;
                    }
                    printf(" from: %s\n",inet_ntoa(tmp_addr.sin_addr));
                }
            }
        break;
        case ICMP_PARAMETERPROB :
            {
                char *tmp_ptr;
                struct sockaddr_in tmp_addr;
                tmp_addr.sin_addr.s_addr = ip->saddr;
                //Here is our original datagram
                tmp_ptr = (char *)icmp + sizeof(struct icmphdr);
                ip = (struct iphdr *)tmp_ptr;
                icmp = (struct icmphdr *)(tmp_ptr + ip->ihl * 4);
                if (icmp->un.echo.id == glob_opts.id){
                    printf("Parameter problem (network problem) from: %s\n",inet_ntoa(tmp_addr.sin_addr));
                }
            }
        break;
        case ICMP_SOURCE_QUENCH :
            {
                char *tmp_ptr;
                struct sockaddr_in tmp_addr;
                tmp_addr.sin_addr.s_addr = ip->saddr;
                //Here is our original datagram
                tmp_ptr = (char *)icmp + sizeof(struct icmphdr);
                ip = (struct iphdr *)tmp_ptr;
                icmp = (struct icmphdr *)(tmp_ptr + ip->ihl * 4);
                if (icmp->un.echo.id == glob_opts.id){
                    printf("Source Quench from: %s\n",inet_ntoa(tmp_addr.sin_addr));
                }
            }
        break;
        case ICMP_REDIRECT :
            {
                char *tmp_ptr;
                struct sockaddr_in tmp_addr,tmp_addr_g;
                tmp_addr.sin_addr.s_addr = ip->saddr;
                tmp_addr_g.sin_addr.s_addr = icmp->un.gateway;
                int code = icmp->code;
                //Here is our original datagram
                tmp_ptr = (char *)icmp + sizeof(struct icmphdr);
                ip = (struct iphdr *)tmp_ptr;
                icmp = (struct icmphdr *)(tmp_ptr + ip->ihl * 4);
                if (icmp->un.echo.id == glob_opts.id){
                    printf("Redirect for the ");
                    switch (code){ 
                        case ICMP_REDIR_NET:
                            printf("Net");
                        break; 
                        case ICMP_REDIR_HOST:
                            printf("Host");
                        break; 
                        case ICMP_REDIR_NETTOS:
                            printf("Net for TOS");
                        break; 
                        case ICMP_REDIR_HOSTTOS:
                            printf("Host for TOS");
                        break;
                        default:
                            printf("0_o strange error");
                        break;
                    }
                    printf(" to %s",inet_ntoa(tmp_addr_g.sin_addr));
                    printf(" from: %s\n",inet_ntoa(tmp_addr.sin_addr));
                }
            }
        break;
        default :
            printf("Unsupported icmp type.\n");
        break;
    }
    return rc;
}

int recv_packet(){
    // It only receives packet and put it into buf
    int rcc = 0;
    buf = malloc(MAX_SIZE);
    glob_opts.freed &= 1;
    int rc = recv(sock, buf, MAX_SIZE, MSG_DONTWAIT);
    if (rc > 0){
        //Message received. Let's parse it!
        struct timeval t_rcvd;
        gettimeofday(&t_rcvd, NULL);
        rcc = parse_msg(&t_rcvd);
    } else {
        free(buf);
        glob_opts.freed |= 2;
        return rcc;
    }
    free(buf);
    glob_opts.freed |= 2;
    return rcc;
}

// It is part from iputil's ping.c
unsigned short in_cksum(unsigned short *addr, int len){
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    while (nleft > 1){
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1){
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

void packets_wait(){
    //Wait for "slow" packets
    int rc = 0;
    int d_delay = 0;
    while((d_delay < glob_opts.time_to_wait) && (glob_opts.sent != glob_opts.rcvd)){
        rc = recv_packet();
        if (rc == 1){
            d_delay = 0;
        }
        wait(1);
        d_delay += 1;
    }
}

void mem_free(){
    if ((glob_opts.freed  & 2 ) == 0){
        free(buf);
    }
    free(packet);
}

void statistics(int i){
    //Wait for "slow" packets, show stat and free memory
    int loss;
    if (glob_opts.sent == 0){  
        loss = 0;
    } else {
        if (glob_opts.sent != glob_opts.rcvd){
            packets_wait();
        }
        loss = 100 - (int)(100*(double)glob_opts.rcvd/(double)glob_opts.sent);
    }
    printf("\n--- Ping %s statistics ---\nsent: %d rcvd: %d loss: %d%%\n",glob_opts.target, glob_opts.sent, glob_opts.rcvd, loss);
    mem_free();
    int c_rc = close(sock);
    if (c_rc == -1){
        p_error("Close sock");
    }
    exit(0);
}

int main(int argc, char **argv){
    if (geteuid()){
        error("Need root privileges.");
    }
    int longindex;
    glob_opts.delay = DELAY;
    glob_opts.time_to_wait = TIME_TO_WAIT;
    glob_opts.record_route = NO_RECORD_ROUTE;
    glob_opts.ttl = TTL;
    glob_opts.help = NO_HELP;
    glob_opts.count = -1;
    glob_opts.sent = 0;
    glob_opts.rcvd = 0;
    glob_opts.source = NULL;
    glob_opts.target = NULL;
    glob_opts.freed = 1;
    glob_opts.quiet = 0;
    signal(SIGINT,statistics);
    int rc = getopt_long(argc,argv,optstr,opts,&longindex);
    while(rc != -1){
        switch(rc){
            case 'D':
                if (optarg == 0){
                    sscanf(argv[optind],"%d",&glob_opts.delay);
                } else {
                    sscanf(optarg,"%d",&glob_opts.delay);
                }
                break;
            case 'q':
                glob_opts.quiet = 1;
                break;
            case 'd':
                if (optarg == 0){
                    glob_opts.target = argv[optind];
                } else {
                    glob_opts.target = optarg;
                }
                break;
            case 'w':
                if (optarg == 0){
                    sscanf(argv[optind],"%d",&glob_opts.time_to_wait);
                } else {
                    sscanf(optarg,"%d",&glob_opts.time_to_wait);
                }
                break;
            case 'c':
                if (optarg == 0){
                    sscanf(argv[optind],"%d",&glob_opts.count);
                } else {
                    sscanf(optarg,"%d",&glob_opts.count);
                }
                break;
            case 't':
                if (optarg == 0){
                    sscanf(argv[optind],"%d",&glob_opts.ttl);
                } else {
                    sscanf(optarg,"%d",&glob_opts.ttl);
                }
                break;
            case 'h':
                glob_opts.help = HELP;
                break;
            case 'R':
                glob_opts.record_route = RECORD_ROUTE;
                break;
            case '?' :
                show_help();
                exit(1);
                break;
        }
        rc = getopt_long(argc,argv,optstr,opts,&longindex);
    }
    if (glob_opts.help == HELP){
        show_help();
        exit(0);
    }
    if (glob_opts.target == NULL){
        error("No target");
    }
//Let's get source addr (Some magic from iputils)
    int m_rc;
    int probe_fd = socket(AF_INET,SOCK_DGRAM,0);
    if (probe_fd == -1){
        p_error("Socket creation magic");
    }
    struct sockaddr_in dst_;
    dst_.sin_family = AF_INET;
    m_rc = connect(probe_fd, (struct sockaddr*)&dst_, sizeof(dst_));
    if (m_rc == -1){
        p_error("Socket connection magic");
    }
    socklen_t alen = sizeof(dst_);
    m_rc = getsockname(probe_fd, (struct sockaddr*)&dst_, &alen);
    if (m_rc == -1){
        p_error("Getsockname magic");
    }
    m_rc = close(probe_fd);
    if (m_rc == -1){
        p_error("Close magic");
    }
    glob_opts.source = inet_ntoa(dst_.sin_addr);
//End of magic
// Resolve target name 
    struct hostent *host;
    host = gethostbyname(glob_opts.target);
    if (host == NULL){
        switch (h_errno){
            case HOST_NOT_FOUND:
                error("Host not found.");
            break;
            case NO_ADDRESS:
                error("The requested name is valid but does not have an IP address.");
            break;
            case NO_RECOVERY:
                error("A nonrecoverable name server error occurred.");
            break;
            case TRY_AGAIN:
                error("A temporary error occurred on an authoritative name server.  Try again later.");
            break;
            default:
                error("You can't see it!");
            break;
        }
    }
    char *addr;
    addr = host->h_addr_list[0];
    sprintf(glob_opts.target, "%d.%d.%d.%d", addr[0]&0xff,addr[1]&0xff,addr[2]&0xff,addr[3]&0xff);
    check_args();
#ifdef DEBUG
    printf("DEBUG: Global options:\n\
        Delay: %d\n\
        Time-to-wait: %d\n\
        RECORD_ROUTE: %d\n\
        TTL: %d\n\
        Count: %d\n\
        Quiet: %d\n\
        Target: %s\n\
        Source: %s\n",glob_opts.delay, glob_opts.time_to_wait, glob_opts.record_route, glob_opts.ttl, glob_opts.count, glob_opts.quiet, glob_opts.target, glob_opts.source);
#endif
// Let's make packet!
    struct iphdr *ip;
    struct rroute_t *ip_rr;
    struct icmphdr *icmp;
    char *data;
    char *packet;
    int packet_size;
    struct sockaddr_in src, dst;
    dst.sin_family = AF_INET;
    inet_aton(glob_opts.source,&src.sin_addr);
    inet_aton(glob_opts.target,&dst.sin_addr);
    if (glob_opts.record_route == RECORD_ROUTE){
        packet_size = sizeof(struct iphdr) + sizeof(struct rroute_t) + sizeof(struct icmphdr) + sizeof(struct timeval);
        packet = malloc(packet_size);
        ip = (struct iphdr *)packet;
        ip_rr = (struct rroute_t *)(packet + sizeof(struct iphdr));
        icmp = (struct icmphdr *)(packet + sizeof(struct iphdr) + sizeof(struct rroute_t));
        data = (packet + packet_size - sizeof(struct timeval));
        ip->ihl = 15;
        ip->tot_len = htons(packet_size);
        ip_rr->nop = 1;
        ip_rr->type = 7;
        ip_rr->length = 39;
        ip_rr->pointer = 8;
        ip_rr->addr[0] = src.sin_addr.s_addr;
    } else {
        packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct timeval);
        packet = malloc(packet_size);
        ip = (struct iphdr *)packet;
        ip_rr = NULL;
        icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
        data = (packet + packet_size - sizeof(struct timeval));
        ip->ihl = 5;
        ip->tot_len = htons(packet_size);
    }
    ip->version = 4;
    ip->tos = 0;
    ip->id = htons(random());
    ip->frag_off = htons(0x4000);
    ip->ttl = glob_opts.ttl;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = src.sin_addr.s_addr;
    ip->daddr = dst.sin_addr.s_addr;
    if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
        p_error("Socket");
    }
    int optval = 1;
    rc = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));
    if (rc == -1){
        p_error("Setsockopt");
    }
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(getpid());
    glob_opts.id = icmp->un.echo.id;
    icmp->un.echo.sequence = 1;
    icmp->checksum = 0;
    ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));
//And now it is time to produce $count packets!
    struct timeval timestamp;
    int d_delay = 0;
    printf("PING: %s\n--------------------\n",glob_opts.target);
    while(glob_opts.count > 0 || glob_opts.count == -1){
        gettimeofday(&timestamp, NULL);
        memcpy(data,&timestamp,sizeof(struct timeval));
        icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + sizeof(struct timeval));
        rc = sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr));
        if (rc == -1){
            p_error("Sendto");
        }
        glob_opts.sent += 1;
        icmp->un.echo.sequence += 1;
        icmp->checksum = 0;
        if (glob_opts.count != -1){
            glob_opts.count -= 1;
        }
        d_delay = 0;
        while(d_delay < glob_opts.delay){
            recv_packet();
            wait(1);
            ++d_delay;
        }
    }
    statistics(0);
    exit(0);
}
