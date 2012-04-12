/*
 * Copyright (c) vecna <vecna@s0ftpj.org> % Sun Aug 29 01:55:06 CEST 2004
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 *
 * this is a library, YOU MUST LINK apmislay-lib.o with your binary, 
 * and include the header tranon-lib.h, 
 *
 * IS - IMPORTANT - FOR - WORKING - AND - PERFORMANCE - OF - THE - PROTOCOL - 
 * THAT - THE - SENDER - IS - ANONYMOUS.
 *
 * IF - THE - RECEIVER - IS - ANONYMOUS - PERFORMANCE - IS - KILLED.
 *
 *
 * I wish to be easy to understand :)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "apmislay.h"

#define MAXFD	32

static struct record_cmd
{
	char command[SML];
	int fd;
} recorded[MAXFD];

void record_ipt_cmd(int fd, char *cmdstr)
{
	int i;

	for(i =0; i < MAXFD; i++)
	{
		if(!recorded[i].fd)
		{
			memcpy(&recorded[i].command, cmdstr, SML);
			recorded[i].fd =fd;

			return;
		}
	}

	/* else ... */
	fprintf(stderr, "sorry, I'm reach limit of %d sessions\n", MAXFD);
	fprintf(stderr, "belive me, this is 0.0.1, linked list on 0.0.2\n");
	fprintf(stderr, "check your iptables by hands :P\n");
}

/* function for compute checksum */
inline unsigned int half_cksum(unsigned short *data, int len)
{
	unsigned int sum =0x00;
	unsigned short carry =0x00;

	while(len > 1)
	{
		sum += *data++;
		len -=2;
	}

	if(len == 1)
	{
		*((unsigned short *) &carry) = *(unsigned char *)data;
		sum +=carry;
	}

	return sum;
}

/* see over */
inline unsigned short compute_sum(unsigned int sum)
{
	sum =(sum >> 16) + (sum & 0xffff);
	sum +=(sum >> 16);

	return (unsigned short) ~sum;
}

/* 
 * tranon_connect is a wrapper of iptables command only,
 * my fault is not manage the cleaning of the rule, sorry :P
 */
int anonymous_connect(int sockfd, const struct sockaddr *sa, socklen_t al, int *child)
{
	/* I'm sorry, the client must retrivere himself him address */
	static unsigned int spoofed;
	char cmdstr[SML], *p;
	int ret, adder, ip_tos =IPTOS_RELIABILITY;

	/* for use the some fake ip source :) */
	if(!spoofed)
	{
		spoofed =inet_addr(ORIGINAL_ADDRESS);

		srandom(time(NULL));

		adder =(random() % IPRANGE);

		p =(unsigned char *)&spoofed;
		p[3] =((p[3] >> IPSHIFT) << IPSHIFT) + adder;

		if(!p[3])
			p[3]++;

		/* if rand() was unluck take next ip */
		if(spoofed ==inet_addr(ORIGINAL_ADDRESS))
			p[3] =((p[3] >> IPSHIFT) << IPSHIFT) + adder +1;

	}

	ret =sprintf(cmdstr, "iptables -t nat -A POSTROUTING -d %s -m tos --tos %d",
			inet_ntoa(((struct sockaddr_in *)sa)->sin_addr),
			ip_tos
		);

	/* DAMN STATIC BUFFER INSIDE inet_* functions !! */
	snprintf(&cmdstr[ret], SML - ret, 
			" -p tcp --dport %d -j SNAT --to-source %s",
			ntohs(((struct sockaddr_in *)sa)->sin_port),
			inet_ntoa(*((struct in_addr *)&spoofed))
		);

	system(cmdstr);
	record_ipt_cmd(sockfd, cmdstr);

	/* RST packet sender - for emulate the other receiver! */
	if(!(*child =fork()))
	{
		unsigned char pktbuff[CAPLEN];
		int rawfd, nbyte, newtime;

		/* I'm reading TCP packet ingoing only */
		rawfd =socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

		while(1)
		{
			unsigned int sum, i;
			struct iphdr *ip;
			struct tcphdr *tcp;
			struct sockaddr_in sin;

			if((nbyte =read(rawfd, pktbuff, CAPLEN)) ==-1)
			{
				fprintf(stderr, "read: %s\n", strerror(errno));
				kill(getppid(), SIGTERM);
			}

			if(nbyte < sizeof(*ip) + sizeof(*tcp))
				continue;

			ip =(struct iphdr *)pktbuff;
			
			if(ip->protocol !=IPPROTO_TCP)
				continue;

			/* remote host is not our receiver! */
			if(ip->saddr !=((struct sockaddr_in *)sa)->sin_addr.s_addr)
				continue;

			tcp =(struct tcphdr *)(pktbuff + ip->ihl *4);

			/* source port is not our looked service */
			if(tcp->source !=((struct sockaddr_in *)sa)->sin_port)
				continue;

			if(!tcp->ack)
				continue;

			/* 
			 * ELSE, is an ACK packet! :), build the answer! 
			 *
			 * this is my test packet:
			 *
			 * tos 0x0, ttl 64, id 52761, offset 0, flags [none], 
			 * length: 40 192.168.1.69.2879 > 192.168.1.1.79: . 
			 * [tcp sum ok] 666:666(0) ack 123 win 512
			 *
			 * and this the receiver answer who I want emulate
			 *
			 * tos 0x0, ttl 64, id 0, offset 0, flags [DF], 
			 * length: 40 192.168.1.1.79 > 192.168.1.69.2879: 
			 * R [tcp sum ok] 123:123(0) win 0
			 *
			 * and this is a common ack from a TCP session:
			 * 
			 * tos 0x0, ttl 64, id 59192, offset 0, flags [DF], 
			 * length: 52 192.168.1.69.43210 > 69.0.209.35.6667: 
			 * . [tcp sum ok] 1:1(0) ack 198 win 501 
			 * <nop,nop,timestamp 197641564 227014700>
			 *
			 * is the some thing with some ip options :P
			 *
			 */

			/* FIN + ACK | SYN + ACK require RST + ACK */
			if(!tcp->fin && !tcp->syn)
			{
				tcp->ack =0;
				tcp->rst =1;
			}
			else
			{
				tcp->ack =1;
				tcp->rst =1;
			}

			ip->id =0;
			ip->tos =0;
			/* tot_len remain the same */
			ip->ttl =DEFAULT_TTL;
			/* ANTANI powered technology! */
			ip->saddr ^=ip->daddr;
			ip->daddr ^=ip->saddr;
			ip->saddr ^=ip->daddr;

			for(i =sizeof(struct iphdr); i < ip->ihl * 4; )
			{
				if(pktbuff[i] != IPOPT_TIMESTAMP)
				{
					/* skip option data and take next */
					i +=pktbuff[i + 1];
				}
				else
				{
					newtime =time(NULL);
					memcpy(&pktbuff[i + 2], &newtime, sizeof(int));
					break;
				}
			}

			tcp->dest ^=tcp->source;
			tcp->source ^=tcp->dest;
			tcp->dest ^=tcp->source;

			tcp->ack_seq = tcp->seq;
			tcp->window =0;
			tcp->seq =0;

			ip->check = tcp->check =0;
			ip->check=half_cksum((unsigned short *)ip, ip->ihl * 4);
			sum =half_cksum((unsigned short *)&ip->saddr, 8);
			sum +=htons(IPPROTO_TCP + nbyte - (ip->ihl * 4));
			tcp->check =compute_sum(sum);

			sin.sin_addr.s_addr =ip->daddr;
			sin.sin_port =tcp->dest;
			sin.sin_family =AF_INET;

			/* blowpipe o========o --> \o/ man */
			/*            poison---^    |      */
			/*                         / \     */
			sendto(rawfd, pktbuff, nbyte, 0, (struct sockaddr *)&sin, sizeof(sin));

			/* sendto return dead soul */
		}
	}

	/* 
	 * put TOS on the socket where apply the spoof :), this is not
	 * for TOS itself, but for select packet to spoof with
	 * iptables tos match extension to avoid spoofing apply on fake
	 * RST packets
	 */
	setsockopt(sockfd, SOL_IP, IP_TOS, &ip_tos, sizeof(ip_tos));

	return connect(sockfd, sa, al);
}

int anonymous_bind(int sockfd, struct sockaddr *my, socklen_t al, int *child)
{
#define TIMEOUT	100 /* milliseconds */
	char errbuf[PCAP_ERRBUF_SIZE], bpf_filter[SML], cmdstr[SML];
	struct sockaddr_in conn;
	struct bpf_program bpf;
	pcap_t *ph;
	int rawfd, clen, client, ip_tos =IPTOS_RELIABILITY, hdr =1;

	if((rawfd =socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) ==-1)
		return -1;

	setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &hdr, sizeof(hdr));
	
	/* init pcap enviroment */
	if((ph =pcap_open_live(NULL, CAPLEN, 0x00, TIMEOUT, errbuf)) ==NULL)
	{
		fprintf(stderr, "file %s: pcap open: %s\n", __FILE__, errbuf);
		errno = -EAFNOSUPPORT;
		return -1;
	}

	memset(bpf_filter, 0x00, SML);

	/* packets with TOS equals to MATCHTOS is selected */
	snprintf(bpf_filter, SML, "src port %d and ip[1:1] != 1", 
		htons(((struct sockaddr_in *)my)->sin_port)
	);

	if(pcap_compile(ph, &bpf, bpf_filter, 0, 0) ==-1)
	{
		fprintf(stderr, "bfp filter: %s\n", pcap_geterr(ph));
		errno = -EPROTONOSUPPORT;
		return -1;
	}

	if(pcap_setfilter(ph, &bpf) ==-1)
	{
		fprintf(stderr, "bpf filter: %s\n", pcap_geterr(ph));
		errno = -EPROTONOSUPPORT;
		return -1;
	}

	snprintf(cmdstr, SML, "iptables -A INPUT -p tcp --dport %d "
			"--tcp-flags RST RST -j DROP",
			ntohs(((struct sockaddr_in *)my)->sin_port)
		);

	system(cmdstr);
	record_ipt_cmd(sockfd, cmdstr);

	/* 
	 * make on background running sniffing server for 
	 * packet replications
	 */
	if(!(*child =fork()))
	{
#define DLINKHDR_OFFSET	16 /* datalink layer offset, for ethernet is 14 + 2 */
		struct pcap_pkthdr pkthdr;
		struct iphdr *ip;
		struct tcphdr *tcp;
		unsigned int original, new, pktlen;
		unsigned char *p, *packet;
		const unsigned char *cp;
		int i;

		packet =malloc(CAPLEN); /* snaplen :) */

		/* the tcp source port is checked from the filter */
		while(1)
		{
			memset(packet, 0x00, CAPLEN);

			/* this code, take ip, bruteforce dest and send */
			cp =pcap_next(ph, &pkthdr);
			pktlen =pkthdr.caplen - DLINKHDR_OFFSET;

			/* this copy because pcap_next return a const ... */
			memcpy(packet, cp + DLINKHDR_OFFSET, pktlen);

			ip =(struct iphdr *)packet;
			tcp =(struct tcphdr *)((unsigned char *)ip + (ip->ihl * 4));

			/* fix orginal value for use on loop */
			new =original =ip->daddr;

			for(i =0; i < IPRANGE; new =original, i++)
			{
				unsigned int sum;
				struct sockaddr_in sin;

				/* ip shifting and computing */
				p =(unsigned char *)&new;
				p[3] =((p[3] >> IPSHIFT) << IPSHIFT) + i;

				/* already send packet */
				if(new ==original)
					continue;

				ip->daddr =new;
				ip->tos =1;

				/* fix check */
				ip->check =tcp->check =0;
				ip->check =half_cksum((unsigned short *)ip, ip->ihl * 4);

				sum =half_cksum((unsigned short *)&ip->saddr, 8);
				sum +=htons(IPPROTO_TCP + pktlen - (ip->ihl * 4));
				sum +=half_cksum((unsigned short *)tcp, pktlen - (ip->ihl * 4));
				tcp->check =compute_sum(sum);

				/* set struct to avoid EDESTADDRREQ with send(2) */
				sin.sin_addr.s_addr =new;
				sin.sin_port =tcp->dest;
				sin.sin_family =AF_INET;

				sendto(rawfd, packet, pktlen, 0, (struct sockaddr_in *)&sin, sizeof(sin));
			}
		}
	}

	if(bind(sockfd, my, al) ==-1)
		return -1;

	listen(sockfd, 1);

	client =accept(sockfd, (struct sockaddr *)&conn, &clen);

	setsockopt(client, SOL_IP, IP_TOS, &ip_tos, sizeof(int));

	return client;
}


void anonymous_close(int fd)
{
	int i;

	for(i =0; i < MAXFD; i++)
	{
		if(recorded[i].fd ==fd)
		{
			*(strchr(recorded[i].command, 'A')) ='D';
			system(recorded[i].command);

			memset(recorded[i].command, 0x00, SML);
			recorded[i].fd =0;

			return;
		}
	}

	/* else */
	fprintf(stderr, "Invalid Parm to anonymous_close: %d\n", fd);
}
