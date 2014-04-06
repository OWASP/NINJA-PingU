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
#include <pthread.h>

#include "conf.h"


/**
 * We provide all Ipv4 IP addresses except the following reserved ranges.
 *
 * 0.0.0.0 – 0.255.255.255
 * 10.0.0.0 – 10.255.255.255
 * 100.64.0.0 – 100.127.255.255
 * 127.0.0.0 – 127.255.255.255
 * 169.254.0.0 – 169.254.255.255
 * 172.16.0.0 – 172.31.255.255
 * 192.0.0.0 – 192.0.0.7
 * 192.0.2.0 – 192.0.2.255
 * 192.88.99.0 – 192.88.99.255
 * 192.168.0.0 – 192.168.255.255
 * 198.18.0.0 – 198.19.255.255
 * 198.51.100.0 – 198.51.100.255
 * 203.0.113.0 – 203.0.113.255
 * 240.0.0.0 – 255.255.255.254
 *
 * source https://en.wikipedia.org/wiki/Reserved_IP_addresses
 */


pthread_mutex_t mutex;
//int seed_ip[3] = 0, b = 0, seed_ip[1] = 0, d = 0;
unsigned int seed_ip[4] = {80,58,0,0};

//seed_ip[3] = 0, seed_ip[2] = 0, seed_ip[1] = 59, seed_ip[0] = 80;
int maxIp[4] = {224,0,0,0};


char *getNext()
{
	//if we reached the limit, returns null
	if( (seed_ip[0] > maxIp[0]) ||
		(seed_ip[0] == maxIp[0] && seed_ip[1] > maxIp[1]) ||
		(seed_ip[0] == maxIp[0] && seed_ip[1] == maxIp[1] && seed_ip[2] > maxIp[2]) ||
		(seed_ip[0] == maxIp[0] && seed_ip[1] == maxIp[1] && seed_ip[2] == maxIp[2] && seed_ip[3] >=maxIp[3]) ) {
		return NULL;
	} else if (seed_ip[3] < 254) {
		seed_ip[3]++;
		if (seed_ip[0] == 192 && seed_ip[1] == 168 && seed_ip[2] == 0 && seed_ip[3] < 8)
		{
			seed_ip[3] = 8;
		}
	} else if (seed_ip[2] < 254) {
		seed_ip[3] = 0;
		seed_ip[2]++;
		if (seed_ip[2] == 2 && seed_ip[1] == 0 && seed_ip[0] == 192) {
			seed_ip[2]++;
		} else if (seed_ip[2] == 100 && seed_ip[1] == 51 && seed_ip[0] == 198) {
			seed_ip[2]++;
		} else if (seed_ip[2] == 113 && seed_ip[1] == 0 && seed_ip[0] == 203) {
			seed_ip[2]++;
		} else if (seed_ip[2] == 99 && seed_ip[1] == 88 && seed_ip[0] == 192) {
			seed_ip[2]++;
		}
	} else if (seed_ip[1] < 254) {
		seed_ip[3] = 0;
		seed_ip[2] = 0;
		seed_ip[1]++;
		if (seed_ip[1] == 168 && seed_ip[3] == 192) {
			seed_ip[1] = 169;
		} else if (seed_ip[1] == 16 && seed_ip[0] == 172) {
			seed_ip[1] = 32;
		} else if (seed_ip[0] == 100 && seed_ip[1] == 64) {
			seed_ip[1] = 128;
		} else if (seed_ip[0] == 198 && seed_ip[1] == 18) {
			seed_ip[1] = 20;
		}
	} else if (seed_ip[0] < 224) {
		seed_ip[3] = 0;
		seed_ip[2] = 0;
		seed_ip[1] = 0;
		seed_ip[0]++;
		if (seed_ip[0] == 10 || seed_ip[0] == 0 || seed_ip[0] == 127) { /*avoid 0.x.x.x, 10.x.x.x and 127.x.x.x.x*/
			seed_ip[0]++;
		}
	} else {
		return NULL;
	}
        char *str;
        str = (char *) malloc(13);
	snprintf(str, 13, "%d.%d.%d.%d", seed_ip[0], seed_ip[1], seed_ip[2], seed_ip[3]);
	return str;
}


void test_getNext()
{
	unsigned long long int counta = 0;
	char *ip = getNext();
	while (ip != NULL)
	{
		counta++;
		free(ip);
		ip = getNext();
		if (counta % 10000000 == 0)
		{
			printf("num %llu  ip   %s\n", counta, ip);
		}
	}
	printf("%llu", counta);
	exit(0);
}

