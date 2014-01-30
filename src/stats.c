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
#include <pthread.h>
#include <semaphore.h>

#include "pers.c"

struct statistics {
	unsigned long long foundHosts;
	unsigned long long attemptedHosts;
};

struct statistics stats;


pthread_mutex_t fLock;
pthread_mutex_t aLock;
pthread_mutex_t sLock;

int statsEnd = FALSE;

void incFoundHosts(int newV) {
	pthread_mutex_lock(&fLock);
	stats.foundHosts = stats.foundHosts+ newV;
	pthread_mutex_unlock(&fLock);
}

void incAttemptedHosts(int newV) {
	pthread_mutex_lock(&aLock);
	stats.attemptedHosts += newV;
	pthread_mutex_unlock(&aLock);
}

void *printstats(void *sem) {
	unsigned long long speed = 0;
	unsigned long long oldAttempted = 0;
	char units;
	openStatsFile();
	fprintf(statsFile, "0 0\n");
	sem_wait((sem_t *)sem);
	printf("\t+Stats     Service Started\n");
	fprintf(statsFile, "%llu %llu\n", stats.attemptedHosts, stats.foundHosts);
	sleep(1);
	fprintf(statsFile, "%llu %llu\n", stats.attemptedHosts, stats.foundHosts);
	printf("\n\n#################\t\t###############\t\t###############\n#Attempted Hosts#\t\t#Found   Hosts#\t\t#    Speed    #\n#################\t\t###############\t\t###############\n");
	unsigned long long atte;
	unsigned long long foun;
	int j;
	int k = DELAY_LISTENER;
	while (statsEnd == FALSE && (endOfScan == FALSE || k >= 0))
	{
		sleep(1);
		if (endOfScan == TRUE) {
			k--;
		}
		speed = stats.attemptedHosts  - oldAttempted;
		atte = stats.attemptedHosts;
		foun = stats.foundHosts;
		if (speed > 1000 && speed < 1000000) {
			units = 'K';
			speed = speed / 1000;
		} else if (speed > 1000000) {
			units = 'M';
			speed = speed /1000000;
		} else {
			units = '\0';
		}
		for (j=0; j < 100; j++)
			printf("\r#%15llu#\t\t#%13llu#\t\t#%3llu%cpkts/sec#", atte, foun, speed, units);
		oldAttempted = stats.attemptedHosts;
		fprintf(statsFile, "%llu %llu\n", stats.attemptedHosts, stats.foundHosts);
	}
	printf("\n#################\t\t###############\t\t###############\n");
	return NULL;
}

