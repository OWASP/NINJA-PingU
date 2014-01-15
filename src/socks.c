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
#include <pthread.h>
#include <sys/socket.h>
#include <semaphore.h>
#include <netinet/tcp.h>


struct host {
	int port;
	char *ip;
} host;


struct agentInfo {
	unsigned  int run; 	//boolean value to stop
	unsigned int mPort; 	//targeted local port
	unsigned int tPort[2];	//targeted scan port range
	char *mIp;		//our local ip address
	sem_t *startB;		//semaphore for synchronization purposes
} agentInfo;

char* getHostBySock(int sock)
{
	struct sockaddr_in local_address;
	int addr_size = sizeof(local_address);
	if (getpeername(sock, (struct sockaddr*) &local_address, (unsigned int*)&addr_size) < 0) {
		//perror("Failed to get peer address");
		return inet_ntoa(local_address.sin_addr);
	}else {
		return inet_ntoa(local_address.sin_addr);
	}
}

int getPortBySock(int sock)
{
	struct sockaddr_in local_address;
	int addr_size = sizeof(local_address);
	if (getpeername(sock, (struct sockaddr*) &local_address, (unsigned int*)&addr_size) < 0) {
		//perror("Failed to get peer address");
		return (int)-1;
	} else {
		return  ((int)ntohs(local_address.sin_port));
	}
}
struct sockaddr_in str2sa(char *str, int port) {
	static struct sockaddr_in sa;
	bzero(&sa, sizeof(sa));
	str = strdup(str);
	if (!inet_aton(str, &sa.sin_addr)) {
		struct hostent *he;
		if ((he = gethostbyname(str)) != NULL) {
			sa.sin_addr = *(struct in_addr *) *(he->h_addr_list);
		}
	}
	sa.sin_port = htons(port);
	sa.sin_family = AF_INET;
	if (str != NULL) {
		free(str);
	}
	return sa;
}

char get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return (int)&(((struct sockaddr_in*) sa)->sin_addr);
	}
	return (int)&(((struct sockaddr_in6*) sa)->sin6_addr);
}

/* create a TCP socket with non blocking options and connect it to the target
 * if succeed, add the socket in the epoll list and exit with 0
 */
int create_and_connect(char *ip, int port, int socksEventDescriptor) {
	int yes = 1;
	int sock;
	// epoll mask that contain the list of epoll events attached to a network socket
	
 struct epoll_event Edgvent;// = malloc(sizeof(char)*50);
	struct sockaddr_in target = str2sa(ip, port);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		//perror("socket is broken");
		return -1;
	}

	//set socket to non blocking and allow port reuse
	if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
		//perror("socket is broken ");
		return -1;
	}

	//additional options here, port reuse
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	//setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
	//setsockopt(sock, IPPROTO_TCP, TCP_SYNCNT, &yes, sizeof(yes));
	//setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &yes, sizeof(yes));
	//setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &yes, sizeof(yes));
	//setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));

	if (connect(sock, (struct sockaddr *) &target, sizeof(struct sockaddr)) == -1 && errno != EINPROGRESS && errno == EAGAIN) {
		create_and_connect(ip, port, socksEventDescriptor);
		return -1;
	} else {
		Edgvent.events = EPOLLOUT | EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLPRI;
		Edgvent.data.fd = sock;
		// add the socket to the epoll file descriptors
		if (epoll_ctl((int) socksEventDescriptor, EPOLL_CTL_ADD, sock, &Edgvent) != 0) {
			create_and_connect(ip, port, socksEventDescriptor);
		}
	}
	return 0;
}

/* reading waiting errors on the socket
 * return 0 if there's no, 1 otherwise
 */
int socket_check(int fd) {
	int ret;
	int code;
	size_t len = sizeof(int);

	ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &code, (socklen_t *)&len);

	if ((ret || code) != 0)
		return 1;

	return 0;
}
int socket_check_timout(int fd) {
	int ret1, ret2;
	int code;
	size_t len = sizeof(int);

	ret1 = getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &code,(socklen_t *) &len);
	ret2 = getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &code,(socklen_t *) &len);

	if ((ret1 || ret2 || code) != 0)
		return 1;

	return 0;
}

void deleteSock(int evSockDesc, int fd) {
	epoll_ctl(evSockDesc, EPOLL_CTL_DEL, fd, NULL);
	close(fd);
}

void push_next_target(int evSockDesc, int fd, int i, char *ip, int port) {
	deleteSock((int)evSockDesc, fd);
	if (create_and_connect(ip, port, evSockDesc) != 0) {
		sleep(1);
	}
	if (ip != NULL) {
		free(ip);
	}
}
