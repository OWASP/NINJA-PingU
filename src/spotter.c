/*   OWASP NINJA PingU: Is Not Just a Ping Utility
 *
 *   Copyright (C) 2014 Guifre Ruiz <guifre.ruiz@owasp.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "utils.c"
#include "connector.c"
#include "conf.h"

struct pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

unsigned short csum(unsigned short *ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*) &oddbyte) = *(u_char*) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short) ~sum;

	return (answer);
}

int getSock() {
	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	return s;
}

void getMeAIPHeader(struct iphdr *iph, char *mIp) {
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->id = htons(0);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(mIp);
}

void getMeATCPHeader(struct tcphdr *tcph, int mPort, int tPort) {
	tcph->source = htons(mPort);
	tcph->dest = htons(tPort);
	tcph->seq = htonl(MAGIC_ACKSEQ - 1);
	tcph->ack_seq = htonl(0);
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(42900);
	tcph->check = 0;
	tcph->urg_ptr = 0;
}

void single_port(char *ip, struct agentInfo *aInfo, struct sockaddr_in *sin, struct tcphdr *tcph,
		struct pseudo_header *psh, char *mDatagram, struct iphdr *iph, int *s) {
	unsigned int tmpAttemptedHosts = 0;
	unsigned int cache_sync = CACHE_SYNC;
	while (endOfScan == FALSE && ip != NULL && aInfo->run == TRUE) {
		sin->sin_addr.s_addr = inet_addr(ip);
		iph->daddr = sin->sin_addr.s_addr;
		iph->check = csum((unsigned short *) mDatagram, iph->tot_len >> 1);
		psh->dest_address = sin->sin_addr.s_addr;
		tcph->source = htons(aInfo->mPort);
		tcph->check = csum((unsigned short*) psh, sizeof(struct pseudo_header));
		sendto(*s, mDatagram, iph->tot_len, 0, (struct sockaddr *) sin, sizeof(*sin));
		tmpAttemptedHosts++;
		if (tmpAttemptedHosts >= cache_sync) {
			incAttemptedHosts(tmpAttemptedHosts);
			tmpAttemptedHosts = 0;
		}
		pthread_mutex_lock (&sLock);
		getNext2(ip);
		pthread_mutex_unlock(&sLock);
	}
}

void single_port_delay(char *ip, struct agentInfo *aInfo, struct sockaddr_in *sin, struct tcphdr *tcph,
		struct pseudo_header *psh, char *mDatagram, struct iphdr *iph, int *s) {
	unsigned int tmpAttemptedHosts = 0;
	unsigned int cache_sync = CACHE_SYNC;
	unsigned long de = delay;
	while (endOfScan == FALSE && ip != NULL && aInfo->run == TRUE) {
		usleep(de);
		sin->sin_addr.s_addr = inet_addr(ip);
		iph->daddr = sin->sin_addr.s_addr;
		iph->check = csum((unsigned short *) mDatagram, iph->tot_len >> 1);
		psh->dest_address = sin->sin_addr.s_addr;
		tcph->source = htons(aInfo->mPort);
		tcph->check = csum((unsigned short*) psh, sizeof(struct pseudo_header));
		sendto(*s, mDatagram, iph->tot_len, 0, (struct sockaddr *) sin, sizeof(*sin));
		tmpAttemptedHosts++;
		if (tmpAttemptedHosts >= cache_sync) {
			incAttemptedHosts(tmpAttemptedHosts);
			tmpAttemptedHosts = 0;
		}
		pthread_mutex_lock (&sLock);
		getNext2(ip);
		pthread_mutex_unlock(&sLock);
	}
}
void multiple_port(char *ip, struct agentInfo *aInfo, struct sockaddr_in *sin, struct tcphdr *tcph,
		struct pseudo_header *psh, char *mDatagram, struct iphdr *iph, int *s) {
	unsigned int tmpAttemptedHosts = 0;
	unsigned int cache_sync = CACHE_SYNC;
	if (aInfo->tPort[1] > aInfo->tPort[0]) {
		int port = aInfo->tPort[0];
		while (endOfScan == FALSE && ip != NULL && aInfo->run == TRUE) {
			iph = (struct iphdr *) mDatagram;
			sin->sin_port = htons(port);
			sin->sin_addr.s_addr = inet_addr(ip);
			iph->daddr = sin->sin_addr.s_addr;
			iph->check = csum((unsigned short *) mDatagram, iph->tot_len >> 1);
			getMeATCPHeader(tcph, aInfo->mPort, port);
			psh->dest_address = sin->sin_addr.s_addr;
			psh->tcp_length = htons(20);
			memcpy(&psh->tcp, tcph, sizeof(struct tcphdr));
			tcph->check = csum((unsigned short*) psh, sizeof(struct pseudo_header));
			sendto(*s, mDatagram, iph->tot_len, 0, (struct sockaddr *) sin, sizeof(*sin));
			tmpAttemptedHosts++;
			if (tmpAttemptedHosts >= cache_sync) {
				incAttemptedHosts(tmpAttemptedHosts);
				tmpAttemptedHosts = 0;
			}
			port++;
			if (port > aInfo->tPort[1]) {
				port = aInfo->tPort[0];
				pthread_mutex_lock (&sLock);
				getNext2(ip);
				pthread_mutex_unlock(&sLock);
			}
		}
	}
}
void multiple_port_delay(char *ip, struct agentInfo *aInfo, struct sockaddr_in *sin, struct tcphdr *tcph,
		struct pseudo_header *psh, char *mDatagram, struct iphdr *iph, int *s) {
	unsigned int tmpAttemptedHosts = 0;
	unsigned int cache_sync = CACHE_SYNC;
	long de = delay;
	if (aInfo->tPort[1] > aInfo->tPort[0]) {
		int port = aInfo->tPort[0];
		while (endOfScan == FALSE && ip != NULL && aInfo->run == TRUE) {
			usleep(de);
			iph = (struct iphdr *) mDatagram;
			sin->sin_port = htons(port);
			sin->sin_addr.s_addr = inet_addr(ip);
			iph->daddr = sin->sin_addr.s_addr;
			iph->check = csum((unsigned short *) mDatagram, iph->tot_len >> 1);
			getMeATCPHeader(tcph, aInfo->mPort, port);
			psh->dest_address = sin->sin_addr.s_addr;
			psh->tcp_length = htons(20);
			memcpy(&psh->tcp, tcph, sizeof(struct tcphdr));
			tcph->check = csum((unsigned short*) psh, sizeof(struct pseudo_header));

			sendto(*s, mDatagram, iph->tot_len, 0, (struct sockaddr *) sin, sizeof(*sin));
			tmpAttemptedHosts++;
			if (tmpAttemptedHosts >= cache_sync) {
				incAttemptedHosts(tmpAttemptedHosts);
				tmpAttemptedHosts = 0;
			}
			port++;
			if (port > aInfo->tPort[1]) {
				port = aInfo->tPort[0];
				
				pthread_mutex_lock (&sLock);
				getNext2(ip);
				pthread_mutex_unlock(&sLock);
			}
		}
	}
}

void *start_sender(void *agentI) {
	struct agentInfo *aInfo = agentI;

	sem_wait(aInfo->startB);
	printf("\t+Spotter   Started at port [%u]\n", aInfo->mPort);

	int s = getSock();

	//Datagram to represent the packet
	char *mDatagram = malloc(sizeof(char) * 4096);

	//IP header

	struct iphdr *iph = (struct iphdr *) mDatagram;
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (mDatagram + sizeof(struct ip));

	struct sockaddr_in sin;
	struct pseudo_header psh;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(aInfo->tPort[0]);
	char *ip = malloc(sizeof(char)*50);
	getNext2(ip);
	sin.sin_addr.s_addr = inet_addr(ip);

	memset(mDatagram, 0, 2096); /* zero out the buffer */

	getMeAIPHeader(iph, aInfo->mIp);
	iph->daddr = sin.sin_addr.s_addr;
	iph->check = csum((unsigned short *) mDatagram, iph->tot_len >> 1);

	//TCP Header
	getMeATCPHeader(tcph, aInfo->mPort, aInfo->tPort[0]);

	psh.source_address = inet_addr(aInfo->mIp);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(20);

	memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

	//checksum
	tcph->check = csum((unsigned short*) &psh, sizeof(struct pseudo_header));

	int one = 1;
	const int *val = &one;
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		printf("\nERROR!!!!!\n\n Error: Need super cow powers to run, sorry :/\n");
		printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
		exit(0);
	}
	//TODO: this should be changed to a normal uid
	//setgid(geteuid());
	//setuid(geteuid());

	if (aInfo->tPort[1] > aInfo->tPort[0]) {
		if (delay == 0) {
			multiple_port(ip, aInfo, &sin, tcph, &psh, mDatagram, iph, &s);
		} else {
			multiple_port_delay(ip, aInfo, &sin, tcph, &psh, mDatagram, iph, &s);
		}
	} else { //if we scan a single port
		if (delay == 0) {
			single_port(ip, aInfo, &sin, tcph, &psh, mDatagram, iph, &s);
		} else {
			single_port_delay(ip, aInfo, &sin, tcph, &psh, mDatagram, iph, &s);
		}

	}
	//sleep(1);
	endOfScan = TRUE;
	aInfo->run = FALSE;
	return NULL;
}

