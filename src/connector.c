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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/timerfd.h>

#include "socks.c"
#include "pluginHandler.c"

// the epoll file descriptor
int epfd;

pthread_mutex_t mutex_epfd = PTHREAD_MUTEX_INITIALIZER;

int *start_connector(void *agentI) {
	struct agentInfo *aInfo = agentI;
	
	//wait for sync
	sem_wait(aInfo->startB);
	printf("\t+Connector Service started [%u]\n", aInfo->mPort);

	openAckFile();
	
	// internal variables definition
	int i, count, datacount;
	
	//buf to hold the response
	char buffer[512];
	int buffersize = sizeof(buffer);

	// epoll structure that will contain the current network socket and event when epoll wakes up
	static struct epoll_event *events;
	static struct epoll_event event_mask;
	
	// create the special epoll file descriptor
	pthread_mutex_lock(&mutex_epfd);
	epfd = epoll_create(MAX_SOCKS);
	pthread_mutex_unlock(&mutex_epfd);

	// allocate enough memory to store all the events in the "events" structure
	if (NULL == (events = calloc(MAX_SOCKS, sizeof(struct epoll_event)))) {
		perror("calloc events");
		exit(1);
	};

	while (endOfScan == FALSE) {

		count = epoll_wait((int )epfd, events, MAX_SOCKS, -1);
		for (i = 0; i < count; i++) {

			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLRDHUP) || (events[i].events & EPOLLHUP)) //socket is erroneous
			{
				deleteSock(epfd, events[i].data.fd);
			}

			if (events[i].events & EPOLLOUT) //we can write
			{
				if (socket_check(events[i].data.fd) != 0) {
					deleteSock(epfd, events[i].data.fd);
					continue;
				} else {
					// Request
					int porr = (int)getPortBySock(events[i].data.fd);
					char *message= malloc(sizeof(char)*80);

					getServiceInput(porr, message);
					int messagelength = strlen(message);
					if ((datacount = send(events[i].data.fd, message, messagelength, 0)) < 0) {
						//printf("send failed");
						continue;
					} else {
						event_mask.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
						event_mask.data.fd = events[i].data.fd;
						if (epoll_ctl((int) epfd, EPOLL_CTL_MOD, events[i].data.fd, &event_mask) != 0) {
							deleteSock(epfd, events[i].data.fd);
							continue;
						}
					}
					if (message != NULL) {
						free(message);
					}
				}
			}
			if ((events[i].events & EPOLLIN)) //we can read
			{
				if (socket_check(events[i].data.fd) != 0) {
					deleteSock(epfd, events[i].data.fd);
					continue;
				} else {
					struct host hostInfo;
					hostInfo.port =  (int)getPortBySock(events[i].data.fd);
					hostInfo.ip =  getHostBySock(events[i].data.fd);
					if (hostInfo.port == -1 || strlen(hostInfo.ip) == 0){
						deleteSock(epfd, events[i].data.fd);
						continue;
					}
					memset(buffer, 0x0, buffersize);
					char *msg;
					msg = (char *) malloc(5000);
					if (msg != NULL) {
						int data = 0, datacount = 0;
						while ((datacount = recv(events[i].data.fd, buffer, buffersize, 0)) > 0) {
							buffer[datacount] = '\0';
							if (data + datacount > 4999) {
								break;
							}
							if (data == 0) {
								strncpy(msg, buffer,4999);
							} else {
								strncat(msg, buffer,4999);
							}
							data = data + datacount;
						}
						if (data > 0) {
							provideOutput(hostInfo.ip, hostInfo.port, msg);
							persistAck(hostInfo.ip,hostInfo.port,msg);
						}
						if (msg!= NULL) {
							free(msg);
						}
					}
					deleteSock(epfd, events[i].data.fd);
				}
			}
			if (events[i].events & EPOLLERR) { //error
				continue;
			}
		}
	}
	onStopPlugin();
	return 0;
}

