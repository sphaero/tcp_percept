/* Copyright (c) 1997-1999 Miller Puckette.
* For information on usage and redistribution, and for a DISCLAIMER OF ALL
* WARRANTIES, see the file, "LICENSE.txt," in this distribution.  */

/* network */

#include "m_pd.h"
#include "s_stuff.h"
#include <stdbool.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>
#include "uthash.h"

/* pcap structs & defines */

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01  //00001
        #define TH_SYN  0x02  //00010
        #define TH_RST  0x04  //00100
        #define TH_PUSH 0x08  //01000
        #define TH_ACK  0x10  //10000
        #define TH_URG  0x20  //etc
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* tcp tacking table */
struct tcp_sess {
    char name[27];   // key: name is "sport:dip:dport"
    int state;		 // see state table
    int note;		 // a midi note in the range 0-127
    UT_hash_handle hh; /* makes this structure hashable */
};
/*
 * State table
 * ==============================
 * id : description   : tcp flags
 * ------------------------------
 * 0  : nothing       :
 * 1  : connect req   : >SYN
 * 2  : connect ack   : <SYN+ACK
 * 3  : connected     : >ACK
 * 4  : sending       : >
 * 5  : receiving     : <
 * 6  : terminate req : >FIN
 * 7  : terminate ack : <FIN+ACK
 * 8  : terminated    : >ACK
 */
#define ST_CONNECT_REQ   1
#define ST_CONNECT_ACK   2
#define ST_CONNECTED     3
#define ST_SENDING       4
#define ST_RECEIVING     5
#define ST_TERMINATE_REQ 6
#define ST_TERMINATE_ACK 7
#define ST_TERMINATED    8

/* PD methods & defines */
static t_class *tcp_percept_class;

typedef struct _tcp_percept
{
    t_object x_obj;
    t_outlet *x_msgout;
    t_outlet *x_connectout;
    int x_nconnections;
    int x_udp;
    int x_bin;
    int pcapfd;
    struct bpf_program fp;
    int *x_connections;
    int x_old;
    char *dev; 				/* capture device name */
    char my_ipaddress[15];  /* device ipaddress */
    pcap_t *handle;			/* packet capture handle */
} t_tcp_percept;

//initialise tcp session table
struct tcp_sess *sess_table = NULL;

//static void tcp_percept_notify(t_tcp_percept *x, int fd)
//{
//    int i;
//    for (i = 0; i < x->x_nconnections; i++)
//    {
//        if (x->x_connections[i] == fd)
//        {
//            memmove(x->x_connections+i, x->x_connections+(i+1),
//                sizeof(int) * (x->x_nconnections - (i+1)));
//            x->x_connections = (int *)t_resizebytes(x->x_connections,
//                x->x_nconnections * sizeof(int),
//                    (x->x_nconnections-1) * sizeof(int));
//            x->x_nconnections--;
//        }
//    }
//    outlet_float(x->x_connectout, x->x_nconnections);
//}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	t_tcp_percept *x = (t_tcp_percept*)args;
	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\n----------------------------------------------------------------\n");
	printf("Packet number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		post("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		post("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	/* print source and destination IP addresses & ports */
	post("       From: %s:%d\n", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
	post("         To: %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

	char tname[27];  // container for our connection identifier
	bool up = false; // up or down direction
	int result = strcmp(inet_ntoa(ip->ip_src), x->my_ipaddress);
	if ( result == 0 )
	{
		// upstream connection
		sprintf(tname, "%d:%s:%d", ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport) );
		printf("\tUp %s\n", tname);
		up = true;
	}
	else
	{
		result = strcmp(inet_ntoa(ip->ip_dst), x->my_ipaddress);
		if ( result == 0 )
		{
			// downstream connection
			sprintf(tname, "%d:%s:%d", ntohs(tcp->th_dport), inet_ntoa(ip->ip_src), ntohs(tcp->th_sport) );
			printf("\tDown %s\n", tname);
			up = false;
		}
		else
		{
			printf("ERROR: neither ip_src or ip_dst matches our ip\n");
			return;
		}
	}
	// save to our session table
	struct tcp_sess *sess;
	// first see if we know this connection
	HASH_FIND_STR( sess_table, tname, sess);
	if (sess == NULL )
	{
		sess = (struct tcp_sess*)malloc(sizeof(struct tcp_sess));
		strcpy(sess->name, tname);
		int n = 100;
		sess->note = n;
		HASH_ADD_STR( sess_table, name, sess );
	}
	else
	{
		sess->note++;
	}
	// Get the state and save it
	printf("      State: %i ", up);

	// new state tmp container
	int new_state = 0;

	if (sess->state == ST_CONNECTED || sess->state == ST_SENDING || sess->state == ST_RECEIVING)
	{
		if (up)
		{
			new_state = ST_SENDING;
		}
		else
		{
			new_state = ST_RECEIVING;
		}
	}
	if ((tcp->th_flags & TH_FIN) == TH_FIN && sess->state != ST_TERMINATE_REQ)
	{
		new_state = ST_TERMINATE_REQ;
		printf(" FIN");
	}
	if ((tcp->th_flags & TH_SYN ) == TH_SYN && sess->state != ST_CONNECT_REQ)
	{
		new_state = ST_CONNECT_REQ;
		printf(" SYN");
	}
	if ((tcp->th_flags & TH_ACK) == TH_ACK)
	{
		if (sess->state == ST_TERMINATE_REQ )
		{
			new_state = ST_TERMINATE_ACK;
		}
		else if (sess->state == ST_CONNECT_REQ )
		{
			new_state = ST_CONNECT_ACK;
		}
		else if (sess->state == ST_CONNECT_ACK)
		{
			new_state = ST_CONNECTED;
		}
		else if (sess->state == ST_TERMINATE_ACK)
		{
			new_state = ST_TERMINATED;
		}
		printf(" ACK");
	}
	if ((tcp->th_flags & TH_RST) == TH_RST)
	{
		printf("NOT HANDLING RESETS!!!!");
		printf(" RST");
	}
	if ((tcp->th_flags & TH_PUSH) == TH_PUSH)
	{
		printf(" PUSH");
	}
	if ((tcp->th_flags & TH_URG) == TH_URG)
	{
		printf(" URG");
	}
	if ((tcp->th_flags & TH_ECE) == TH_ECE)
	{
		printf(" ECE");
	}
	if ((tcp->th_flags & TH_CWR) == TH_CWR)
	{
		printf(" CWR");
	}
	printf(" %u\n", tcp->th_flags );

	if (new_state)
		sess->state = new_state;

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	// Use this to set volume or velocity
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	//iteration example
	//for(sess=tcpsess; sess != NULL; sess=sess->hh.next) {
	//	printf("id name: %s note: %i, state: %i\n", sess->name, sess->note, sess->state);
	//}

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	//if (size_payload > 0) {
	//	printf("   Payload (%d bytes):\n", size_payload);
	//	print_payload(payload, size_payload);
	//}

	return;
}

static void tcp_percept_readbin(t_tcp_percept *x, int fd)
{
	pcap_dispatch(x->handle, fd, got_packet, (u_char*)x);

//    unsigned char inbuf[MAXPDSTRING];
//    int ret = recv(fd, inbuf, MAXPDSTRING, 0), i;
//    if (!x->x_msgout)
//    {
//        bug("tcp_percept_readbin");
//        return;
//    }
//    if (ret <= 0)
//    {
//        if (ret < 0)
//            sys_sockerror("recv");
//        sys_rmpollfn(fd);
//        sys_closesocket(fd);
//        tcp_percept_notify(x, fd);
//    }
//    else if (x->x_udp)
//    {
//        t_atom *ap = (t_atom *)alloca(ret * sizeof(t_atom));
//        for (i = 0; i < ret; i++)
//            SETFLOAT(ap+i, inbuf[i]);
//        outlet_list(x->x_msgout, 0, ret, ap);
//    }
//    else
//    {
//        for (i = 0; i < ret; i++)
//            outlet_float(x->x_msgout, inbuf[i]);
//    }
}

//static void tcp_percept_doit(void *z, t_binbuf *b)
//{
//    t_atom messbuf[1024];
//    t_tcp_percept *x = (t_tcp_percept *)z;
//    int msg, natom = binbuf_getnatom(b);
//    t_atom *at = binbuf_getvec(b);
//    for (msg = 0; msg < natom;)
//    {
//        int emsg;
//        for (emsg = msg; emsg < natom && at[emsg].a_type != A_COMMA
//            && at[emsg].a_type != A_SEMI; emsg++)
//                ;
//        if (emsg > msg)
//        {
//            int i;
//            for (i = msg; i < emsg; i++)
//                if (at[i].a_type == A_DOLLAR || at[i].a_type == A_DOLLSYM)
//            {
//                pd_error(x, "tcp_percept: got dollar sign in message");
//                goto nodice;
//            }
//            if (at[msg].a_type == A_FLOAT)
//            {
//                if (emsg > msg + 1)
//                    outlet_list(x->x_msgout, 0, emsg-msg, at + msg);
//                else outlet_float(x->x_msgout, at[msg].a_w.w_float);
//            }
//            else if (at[msg].a_type == A_SYMBOL)
//                outlet_anything(x->x_msgout, at[msg].a_w.w_symbol,
//                    emsg-msg-1, at + msg + 1);
//        }
//    nodice:
//        msg = emsg + 1;
//    }
//}

//static void tcp_percept_connectpoll(t_tcp_percept *x)
//{
//    int fd = accept(x->x_sockfd, 0, 0);
//    if (fd < 0) post("tcp_percept: accept failed");
//    else
//    {
//        int nconnections = x->x_nconnections+1;
//
//        x->x_connections = (int *)t_resizebytes(x->x_connections,
//            x->x_nconnections * sizeof(int), nconnections * sizeof(int));
//        x->x_connections[x->x_nconnections] = fd;
//        if (x->x_bin)
//            sys_addpollfn(fd, (t_fdpollfn)tcp_percept_readbin, x);
//        else
//        {
//            t_socketreceiver *y = socketreceiver_new((void *)x,
//            (t_socketnotifier)tcp_percept_notify,
//                (x->x_msgout ? tcp_percept_doit : 0), 0);
//            sys_addpollfn(fd, (t_fdpollfn)socketreceiver_read, y);
//        }
//        outlet_float(x->x_connectout, (x->x_nconnections = nconnections));
//    }
//}

static void tcp_percept_closeall(t_tcp_percept *x)
{
	pcap_freecode(&x->fp);
	if (x->handle)
		pcap_close(x->handle);
	sys_rmpollfn(x->pcapfd);
//    int i;
//    for (i = 0; i < x->x_nconnections; i++)
//    {
//        sys_rmpollfn(x->x_connections[i]);
//        sys_closesocket(x->x_connections[i]);
//    }
//    x->x_connections = (int *)t_resizebytes(x->x_connections,
//        x->x_nconnections * sizeof(int), 0);
//    x->x_nconnections = 0;
//    if (x->x_sockfd >= 0)
//    {
//        sys_rmpollfn(x->x_sockfd);
//        sys_closesocket(x->x_sockfd);
//    }
//    x->x_sockfd = -1;
}

static void tcp_percept_listen(t_tcp_percept *x)
{
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    char filter_exp[] = "tcp port 25"; 	/* filter expression [3] */
    struct bpf_program fp;				/* compiled filter program (expression) */
    bpf_u_int32 mask;					/* subnet mask */
    bpf_u_int32 net;					/* ip */

    // cleanup on start
    //tcp_percept_closeall(x);

    if (pcap_lookupnet(x->dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
			x->dev, errbuf);
		net = 0;
		mask = 0;
	}
    /* get ipadress of interface */
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;
	/* I want IP address attached to dev */
	strncpy(ifr.ifr_name, x->dev, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	sprintf(x->my_ipaddress, "%s", inet_ntoa((
			(struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	/* print capture info */
	post("Device: %s\n", x->dev);
	post("Device IP: %s\n", x->my_ipaddress);
	//post("Number of packets: %d\n", num_packets);
	post("Filter expression: %s\n", filter_exp);

	x->handle = pcap_open_live(x->dev, SNAP_LEN, 1, 1000, errbuf);
	if (x->handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", x->dev, errbuf);
		exit(EXIT_FAILURE);
	}
	// set non blocking for polling
	pcap_setnonblock(x->handle, true, errbuf);

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(x->handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", x->dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(x->handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp, pcap_geterr(x->handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(x->handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp, pcap_geterr(x->handle));
		exit(EXIT_FAILURE);
	}

	// get pcap fd
	x->pcapfd = pcap_fileno(x->handle);
	fd_set rfds;

	sys_addpollfn(x->pcapfd, (t_fdpollfn)tcp_percept_readbin, x);


	////////OLD

//	if (portno <= 0)
//        return;
//    x->x_sockfd = socket(AF_INET, (x->x_udp ? SOCK_DGRAM : SOCK_STREAM), 0);
//    if (x->x_sockfd < 0)
//    {
//        sys_sockerror("socket");
//        return;
//    }
//#if 0
//    fprintf(stderr, "receive socket %d\n", x->x_ sockfd);
//#endif
//
//#if 1
//        /* ask OS to allow another Pd to repoen this port after we close it. */
//    intarg = 1;
//    if (setsockopt(x->x_sockfd, SOL_SOCKET, SO_REUSEADDR,
//        (char *)&intarg, sizeof(intarg)) < 0)
//            post("tcp_percept: setsockopt (SO_REUSEADDR) failed\n");
//#endif
//#if 0
//    intarg = 0;
//    if (setsockopt(x->x_sockfd, SOL_SOCKET, SO_RCVBUF,
//        &intarg, sizeof(intarg)) < 0)
//            post("setsockopt (SO_RCVBUF) failed\n");
//#endif
//    intarg = 1;
//    if (setsockopt(x->x_sockfd, SOL_SOCKET, SO_BROADCAST,
//        (const void *)&intarg, sizeof(intarg)) < 0)
//            post("tcp_percept: failed to sett SO_BROADCAST");
//        /* Stream (TCP) sockets are set NODELAY */
//    if (!x->x_udp)
//    {
//        intarg = 1;
//        if (setsockopt(x->x_sockfd, IPPROTO_TCP, TCP_NODELAY,
//            (char *)&intarg, sizeof(intarg)) < 0)
//                post("setsockopt (TCP_NODELAY) failed\n");
//    }
//        /* assign server port number etc */
//    server.sin_family = AF_INET;
//    server.sin_addr.s_addr = INADDR_ANY;
//    server.sin_port = htons((u_short)portno);
//
//        /* name the socket */
//    if (bind(x->x_sockfd, (struct sockaddr *)&server, sizeof(server)) < 0)
//    {
//        sys_sockerror("bind");
//        sys_closesocket(x->x_sockfd);
//        x->x_sockfd = -1;
//        return;
//    }
//
//    if (x->x_udp)        /* datagram protocol */
//    {
//        if (x->x_bin)
//            sys_addpollfn(x->x_sockfd, (t_fdpollfn)tcp_percept_readbin, x);
//        else
//        {
//            t_socketreceiver *y = socketreceiver_new((void *)x,
//                (t_socketnotifier)tcp_percept_notify,
//                    (x->x_msgout ? tcp_percept_doit : 0), 1);
//            sys_addpollfn(x->x_sockfd, (t_fdpollfn)socketreceiver_read, y);
//            x->x_connectout = 0;
//        }
//    }
//    else        /* streaming protocol */
//    {
//        if (listen(x->x_sockfd, 5) < 0)
//        {
//            sys_sockerror("listen");
//            sys_closesocket(x->x_sockfd);
//            x->x_sockfd = -1;
//        }
//        else
//        {
//            sys_addpollfn(x->x_sockfd, (t_fdpollfn)tcp_percept_connectpoll, x);
//            x->x_connectout = outlet_new(&x->x_obj, &s_float);
//        }
//    }
}

static void *tcp_percept_new(t_symbol *s, int argc, t_atom *argv)
{
    t_tcp_percept *x = (t_tcp_percept *)pd_new(tcp_percept_class);
    x->dev = "wlan0";		/* capture device name */
    tcp_percept_listen(x);
/*
    int portno = 0;
    x->x_udp = 0;
    x->x_old = 0;
    x->x_bin = 0;
    x->x_nconnections = 0;
    x->x_connections = (int *)t_getbytes(0);
    x->x_sockfd = -1;
    if (argc && argv->a_type == A_FLOAT)
    {
        portno = atom_getfloatarg(0, argc, argv);
        x->x_udp = (atom_getfloatarg(1, argc, argv) != 0);
        x->x_old = (!strcmp(atom_getsymbolarg(2, argc, argv)->s_name, "old"));
        argc = 0;
    }
    else 
    {
        while (argc && argv->a_type == A_SYMBOL &&
            *argv->a_w.w_symbol->s_name == '-')
        {
            if (!strcmp(argv->a_w.w_symbol->s_name, "-b"))
                x->x_bin = 1;
            else if (!strcmp(argv->a_w.w_symbol->s_name, "-u"))
                x->x_udp = 1;
            else
            {
                pd_error(x, "tcp_percept: unknown flag ...");
                postatom(argc, argv); endpost();
            }
            argc--; argv++;
        }
    }
    if (argc && argv->a_type == A_FLOAT)
        portno = argv->a_w.w_float, argc--, argv++;
    if (argc)
    {
        pd_error(x, "tcp_percept: extra arguments ignored:");
        postatom(argc, argv); endpost();
    }
    if (x->x_old)
    {
         old style, nonsecure version
        x->x_msgout = 0;
    }
    else x->x_msgout = outlet_new(&x->x_obj, &s_anything);
         create a socket
    if (portno > 0)
        tcp_percept_listen(x, portno);
*/
    return (x);
}

void tcp_percept_setup(void)
{
    tcp_percept_class = class_new(gensym("tcp_percept"),
        (t_newmethod)tcp_percept_new, (t_method)tcp_percept_closeall,
        sizeof(t_tcp_percept), 0, A_GIMME, 0);
    class_addmethod(tcp_percept_class, (t_method)tcp_percept_listen,
        gensym("listen"), A_FLOAT, 0);
}

/*void x_net_setup(void)
{
    netsend_setup();
    tcp_percept_setup();
}*/

