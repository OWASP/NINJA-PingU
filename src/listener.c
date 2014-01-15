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

#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "spotter.c"

int mSocket;
FILE *logfile;
int i, j;
struct sockaddr_in source, dest;


void createSock() {
	mSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (mSocket < 0) {
		printf("Socket Error\n");
		exit(1);
	}
}
void *start_receiver(void *agentI) {
	struct agentInfo *aInfo = agentI;
	sem_wait(aInfo->startB);
	printf("\t+Listener  Started at port [%u]\n", aInfo->mPort);

	openSynFile();

	int saddr_size, data_size;
	struct sockaddr saddr;

	char *mBuffer = (char *) malloc(80000);

	//creates the socket
	createSock();

	//tmp cache to hold results
	int tmpFoundHosts = 0;

	//main loop
	while (endOfScan == FALSE) {
		saddr_size = sizeof saddr;

		//recieve packets
		data_size = recvfrom(mSocket, mBuffer, 65536, 0, &saddr, (socklen_t*) &saddr_size);
		if (data_size < 0) {
			printf("Recvfrom error , failed to get packets\n");
			exit(1);
		}

		struct iphdr *iph = (struct iphdr*) mBuffer;
		unsigned short iphdrlen;
		iphdrlen = iph->ihl * 4;
		struct tcphdr *tcph = (struct tcphdr*) (mBuffer + iphdrlen);

		//we uniquely identify packets by magic port and magic ack seq number	
		if ((unsigned int) tcph->ack == 1 &&
					 ntohs(tcph->dest) == aInfo->mPort &&
					 ntohl(tcph->ack_seq) == MAGIC_ACKSEQ) {
			//port open
			if ((unsigned int) tcph->rst  == 0 ) {
				struct iphdr *iph = (struct iphdr *) mBuffer;
				iphdrlen = (int) iph->ihl * 4;
				memset(&source, 0, sizeof(source));
				source.sin_addr.s_addr = (unsigned int) iph->saddr;
				memset(&dest, 0, sizeof(dest));
				dest.sin_addr.s_addr = iph->daddr;

				if (synOnly == FALSE) {
					pthread_mutex_lock (&mutex_epfd);
					while (create_and_connect(inet_ntoa(source.sin_addr), ntohs(tcph->source), epfd) != 0) {
						//printf("problem");
					} 
					pthread_mutex_unlock (&mutex_epfd);
				}
				
				//increments counter result
				tmpFoundHosts++;
				if (tmpFoundHosts >= CACHE_SYNC) {
					incFoundHosts(tmpFoundHosts);
					tmpFoundHosts = 0;
				}
				//persists results
				persistSyn(inet_ntoa(source.sin_addr), ntohs(tcph->source));
			} else { //port closed
				//persists results
				//persistClosedSyn(inet_ntoa(source.sin_addr), ntohs(tcph->source));
			}
		} else { //uncomment for debugging purposes
			/*struct iphdr *iph = (struct iphdr *) mBuffer;
			iphdrlen = (int) iph->ihl * 4;
			memset(&source, 0, sizeof(source));
			source.sin_addr.s_addr = (unsigned int) iph->saddr;
			memset(&dest, 0, sizeof(dest));
			dest.sin_addr.s_addr = iph->daddr;
			printf("\nTo[%d] From[%s:%d] syn[%d] ack[%d] rst[%d] ack_seq[%d] fin[%d]\n",tcph->source,inet_ntoa(source.sin_addr),
			ntohs(tcph->source), (unsigned int) tcph->syn,(unsigned int) tcph->ack,(unsigned int) tcph->rst,ntohl(tcph->ack_seq),(unsigned int) tcph->fin );
			*/
		}
	}
	close(mSocket);
	return NULL;
}
