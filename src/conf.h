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


//number of sender threads per receivers
#define RCVR_X_SNDR 300

//seed for socke ports
#define MAGIC_PORT 54321

//our magic seq ack num
#define MAGIC_ACKSEQ 1234

//maximum sockets for epoll
#define MAX_SOCKS 200000

#define DELAY_LISTENER 4

#define RATIO 1;

//use a bigger buffer to avoid I/O  latency i.e. 60000
#define DISK_BUFFER_SIZE 3

//file to persist attempted&found hosts per time unit
#define STATS_FILE "out/stats.out"

//file to persist the alive targets
#define RESULTS_FILE "out/hostsScanned.out"

//file to persist the scanned services
#define RESULTS2_FILE "out/debug.out"

//file to persist the scanned services
#define RESULTS3_FILE "out/servicesScanned.out"

//file to persist special scanned services
#define RESULTS4_FILE "out/specialServicesScanned.out"

//services unknown
#define UNKNOWN "UNKNOWN"

//cache size to hold temporary data withing the thread (the bigger the less sync)
#define CACHE_SYNC  10

//my boolean algebra
#define TRUE 1
#define FALSE 0

#ifndef trick
#define trick
int endOfScan = FALSE;
long delay = 0;
char *module;
static int synOnly = FALSE;
struct plugIn {
	unsigned int ports[2];
};
#endif
