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
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>


#include "listener.c"
#include "gnuplotAgent.c"


void parseIpAddresses(char *in)
{
	 char *pch = strtok (in," ,.-");
	 int i = 0, j=0;
	  while (pch != NULL)
	  {
		  if (i < 4) {
			  seed_ip[i] = atoi(pch);
			  i++;
		  } else {
			  maxIp[j] = atoi(pch);
			  i++;
			  j++;
		  }
		  pch = strtok (NULL, " ,.-");
	  }
	  if (i >=8)
	  {
		  printf("\t+Start Scan Range \t\t\t[%d.%d.%d.%d]\n", seed_ip[0], seed_ip[1], seed_ip[2], seed_ip[3]);
		  printf("\t+Stop Scan Range \t\t\t[%d.%d.%d.%d]\n", maxIp[0], maxIp[1], maxIp[2], maxIp[3]);
	  }
	  if (i < 5){
		  printf("\t+Scanning host \t\t\t[%d.%d.%d.%d]\n", seed_ip[0], seed_ip[1], seed_ip[2], seed_ip[3]);
		  seed_ip[3]--;
		  for(i=0; i < 4; i++)
			maxIp[i] = seed_ip[i];
	  }
	  maxOct=malloc(sizeof(char)*30);
	  snprintf(maxOct, 199, "%d.%d.%d.%d", maxIp[0], maxIp[1], maxIp[2], maxIp[3]);
}

void parsePorts(unsigned int* ports[2], char *in)
{
	char * token = strtok(in, "-");
	(*ports)[0] = (unsigned int)atoi(token);
	token = strtok(NULL, "-");
	if (token != NULL) {
		(*ports)[1] = (unsigned int)atoi(token);
		printf("\t+Enumerating services from port range\t[%u] to [%u]\n", (*ports)[0], (*ports)[1]);
	} else {
		(*ports)[0] = (unsigned int)atoi(in);
		printf("\t+Enumerating services at port\t\t[%u]\n", (*ports)[0]);
	}
}

void printUsage(int args, char *bin)
{
	printf("Usage\n======\n\n sudo %s [OPTIONS] targets\n\n"
			"OPTIONS\n========\n\n"
			"-t\tNumber of spotter threads(i.e. 3).\n"
			"-p\tPort scan range (i.e. 80 or 20-80).\n"
			"-d\tDelay between packages sent in us(i.e. 100).\n"
			"-s\tNo service discoverage (less bandwith load).\n"
			"-m\tModule to run. For instance, Service.\n"
			"-h\tShow this help.\n\n"
			"\tIp address seed (i.e. 192.168.01).\n"
			"Examples\n========\n\n %s -t 5 -p 80 -s 74.125.0.0-74.125.255.255 #SYN scan Google Servers\n\n"
			" %s -t 3 -p 20-80 188.160.0.0-200.0.0.0 -d 1 -m Service #Service Discoverage Plugin\n\n"
			" %s -t 2 1.1.1.1-255.1.1.1 -m Backdoor32764 -p 32764 #32764/TCP Backdoor Plugin\n\n"
			" %s -t 1 200.10.1.1-220.0.0.0 -m VulnScanner -d 1400\n\n", bin, bin, bin, bin, bin);
	exit(0);
}

void checkArgsLength(int args, char *bin)
{
	if (args < 5) {
		printUsage(args, bin);
	}
}

//checks if we reached the limit of hosts to scan
void checkStop()
{
	for (;;) {
		if (endOfScan == TRUE) {
			break;
		} else {
			sleep(2);
		}
	}
}


int isValidIpAddress(char *ipAddress)
{
	char tmp[100];
	strncpy(tmp, ipAddress, 100);
	char *pch = strtok(tmp, "-");
	struct sockaddr_in sa;
	int result;
	if (pch != NULL) {
		result = inet_pton(AF_INET, pch, &(sa.sin_addr));
		if (result != 0) {
			return 1;
		}
		pch = strtok(NULL, "-");
	}

	return 0;
}
void interrupt(int signal_id)
{
	if (endOfScan == TRUE) {
		printf("\n\nCatched Stop Signal. Something wrong happened, you sir have a nice day.\n");
		exit(0);
	}
	if (signal_id == 2) {
		statsEnd = TRUE;
        	endOfScan = TRUE;
        	sleep(1);
		printf("\n\nCatched Stop Signal. Gratefully stopping, you sir have a nice day.\n");
	} else {
		printf("\n\nCatched unknwon signal [%d] Ignoring it.\n\n ", signal_id);
	}
}

char *getMeALocalAddr()
{
	int moreThanOneIF = FALSE;
	int moreThanOneWIF = FALSE;
	char *wlan = NULL;
	char *lan = NULL;

	struct ifaddrs *ifaddr, *ifa;
	int family, saa;
	char host[NI_MAXHOST];
	if (getifaddrs(&ifaddr) == -1) {
	   perror("getifaddrs");
	   exit(EXIT_FAILURE);
	}
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		family = ifa->ifa_addr->sa_family;
		if (family == AF_INET) {
			saa = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
			host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (saa != 0) {
				exit(EXIT_FAILURE);
			}
			if (strstr(ifa->ifa_name, "eth") != NULL) {
				if (lan != NULL) {
					moreThanOneIF = TRUE;
				}
				lan = malloc( 50 * sizeof(char));
				strncpy(lan ,host, 50);
			}
			if (strstr(ifa->ifa_name, "wlan")  != NULL) {
				if (wlan != NULL) {
					moreThanOneWIF = TRUE;
				}
				wlan = malloc(50*sizeof(char));
				strncpy(wlan ,host, 50);
			}
		}
		
	}
	if (moreThanOneIF == FALSE && lan != NULL) {
		return lan;
	} else if (moreThanOneWIF == FALSE && lan == NULL && wlan != NULL) {
		return wlan;
	} else {
		printf("I found several potential local interfaces to use, please write the local ip to use:\n");
		scanf("%s", lan);
		return lan;
	}
}

void closeFiles()
{
	closeServFile();
	closeSynFile();
	closeAckFile();
}


int main(int args, char **argv) {
	
    //variables to hold execution time data
    struct timeval  tv1, tv2;
	


    // catch SIGINT to exit in a clean way
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = interrupt;
    sigemptyset(&(sa.sa_mask));
    if (sigaction(SIGINT, &sa, NULL) != 0) {
            perror("sigaction failed");
            exit(1);
    }

	//check #args correctness
	checkArgsLength(args, argv[0]);

	//data initialization
	char *mIp = NULL;
	unsigned int sendT = 1;
	unsigned int recT = 0;
	unsigned int* ports[2];
	ports[0] = malloc(sizeof(int));
	ports[1] = malloc(sizeof(int));
	(*ports)[0] = (unsigned int)0;
	(*ports)[1] = (unsigned int)0;
	stats.foundHosts = 0;
	
	//parse args
	printf("##################################################################\n#          OWASP NINJA PingU Is Not Just A Ping Utility          #\n##################################################################\nJob Parameters:\n");

	for (i = 0; i < args; i++) {
		if (strcmp(argv[i], "-l") == 0) {
			mIp = argv[i + 1];
			printf("\t+Local IP \t\t\t\t[%s]\n", mIp);
		}
		if (strcmp(argv[i], "-t") == 0) {
			sendT =(unsigned int)atoi(argv[i+1]);
			recT = sendT / RCVR_X_SNDR;
			if (recT == 0)
				recT = 1;
			printf("\t+Spotter Threads \t\t\t[%u]\n", (unsigned int)sendT);
			printf("\t+Listener Threads \t\t\t[%u]\n", (unsigned int)recT);
		}
		if (strcmp(argv[i], "-p") == 0) {
			parsePorts(ports, argv[i+1]);
		}
		if (isValidIpAddress(argv[i])) {
			parseIpAddresses(argv[i]);
		}
		if (strcmp(argv[i], "-d") == 0) {
			delay = atof(argv[i + 1]);
		}
		if (strcmp(argv[i], "-s") == 0) {
			synOnly = TRUE;
		} 
		
		if (strcmp(argv[i], "-h") == 0) {
			printUsage(args, argv[0]);
		}
		if (strcmp(argv[i], "-m") == 0) {
			module = argv[i+1];
			printf("\t+Module \t\t\t\t[%s]\n", module);
		}
	}

	// dynamically load plugin
	loadMethods();
	struct plugIn *plIn = onInitPlugin();
	if (plIn != NULL && (*ports)[0] == 0 && (*ports)[1] == 0)
	{
		(*ports)[0] = plIn->ports[0];
		(*ports)[1] = plIn->ports[1];
	}
	if (ports[0] == 0) {
		(*ports)[0] = (unsigned int) 1;
		(*ports)[1] = (unsigned int) 100;
						
	}
	if (mIp == NULL)
	{
		mIp = getMeALocalAddr();
		printf("\t+Local IP \t\t\t\t[%s]\n", mIp);
	}
	if ((*ports)[1] == 0) {
		printf("\t+Targetting Port \t\t\t\t[%d]\n", (*ports)[0]);
	} else {
		printf("\t+Targetting Port Range \t\t\t[%d-%d]\n", (*ports)[0], (*ports)[1]);
	}
	printf("##################################################################\n");
	
	//semaphore for synchronization purposes
	sem_t s;
	sem_init(&s, 0, 0);

	//struct to hold shared data 
	struct agentInfo *aInfo[10];
	
	//threads declaration
	pthread_t senders[sendT];
	pthread_t analyzer;
	pthread_t receivers[recT];
	pthread_t statsprinter;
	
	printf("Job Agents Creation:\n");
	int i = 0;
	int j = -1;
	
	for (i = 0; i < sendT; i++) {
		if (i % RCVR_X_SNDR == 0) {
			j++;
			aInfo[j] = malloc(sizeof(int) * 4 + sizeof(sem_t) + sizeof(char *) * 30);
			aInfo[j]->mIp = mIp;
			aInfo[j]->mPort = (unsigned int)MAGIC_PORT +(unsigned int) i / (unsigned int)RCVR_X_SNDR;
			aInfo[j]->tPort[0] = (*ports)[0];
			aInfo[j]->tPort[1] = (*ports)[1];
			aInfo[j]->startB = &s;
			aInfo[j]->run = TRUE;
			pthread_create(&receivers[i / RCVR_X_SNDR], NULL, *start_receiver, (void *) aInfo[j]);
			if (synOnly == FALSE) {
				pthread_create(&analyzer, NULL,(void *) *start_connector,  (void *) aInfo[j]);
			}
		}
		pthread_create(&senders[i], NULL, *start_sender, (void *) aInfo[j]);
	}
	
	pthread_create(&statsprinter, NULL, *printstats, (void *) &s);
        char *firstIp;
	firstIp = (char *) malloc(19 * sizeof(char));
	snprintf(firstIp, 199, "%d.%d.%d.%d", seed_ip[0], seed_ip[1], seed_ip[2], seed_ip[3]);

	//wait for threads creation
	for (i = 0; i < sendT+6; i++)
		sem_post(&s);
	sleep(1);
	printf("##################################################################\n");
	
	gettimeofday(&tv1, NULL);
	checkStop();
	gettimeofday(&tv2, NULL);
	double analysisTime = (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec);

	//notify stop
	for (i = 0; i <= j; i++) {
		pthread_mutex_lock(&sLock);
		aInfo[i]->run = FALSE;
		pthread_mutex_unlock(&sLock);
	
	}

	//we for the threads
	for (i = 0; i < sendT; i++) {
		pthread_join(senders[i], NULL);
	}
	for (i = 0; i < recT; i++) {
		pthread_join(receivers[i], NULL);
	}

	pthread_join(statsprinter, NULL);

	//close results descriptors
	closeFiles();

	printf ("\nAnalyzed [%llu]Hosts  and found [%llu]Hosts\n", stats.attemptedHosts,  stats.foundHosts);

	//make some cool plots
	make_plot(firstIp, ports);
	
	//and bye
	printf ("\nAnalysis Time [%f] seconds. Analyzed [%f]Hosts/second Found [%f]Hosts/second\n",
			analysisTime, stats.attemptedHosts/ analysisTime, stats.foundHosts/analysisTime);
	printf("\nResults stored in:\n\t* %s\n\t* %s\n\t* %s\n\t* %s\n\t* %s\n\n",
			RESULTS_FILE, RESULTS2_FILE, RESULTS3_FILE, RESULTS4_FILE, STATS_FILE);
	return 0;
}
