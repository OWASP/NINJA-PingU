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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "conf.h"

FILE *synF;
FILE *ackF;
FILE *servF;
FILE *specServF;
FILE *statsFile;

char buff[DISK_BUFFER_SIZE];
char buff2[DISK_BUFFER_SIZE];
char buff3[DISK_BUFFER_SIZE];
char buff4[DISK_BUFFER_SIZE];
char buff5[DISK_BUFFER_SIZE];

void deblank(char* input) {
	char *output = input;
	int j=0;
	int i=0;
	while( i <= strlen(input)) {
		if (input[i] != '\n' && input[i] != '\r' && input[i] != '\t') {
			output[j] = input[i];
		} else {
			output[j] = ' ';
		}
		j++;
		i++;
	}
	output[j] = 0;
	input = output;
}

void openSynFile() {
	synF = fopen(RESULTS_FILE, "w");
	if (synF == NULL) {
		printf("Error opening file!\n");
		exit(1);
	}
	setvbuf(synF, buff, _IOFBF, DISK_BUFFER_SIZE);// fully buffered
}

void openAckFile() {
	ackF = fopen(RESULTS2_FILE, "w");
	if (ackF == NULL) {
		printf("Error opening file!\n");
		exit(1);
	}
	setvbuf(ackF, buff2, _IOFBF, DISK_BUFFER_SIZE);// fully buffered
}

void openServiceFile() {
	servF = fopen(RESULTS3_FILE, "w");
	if (servF == NULL) {
		printf("Error opening file!\n");
		exit(1);
	}
	setvbuf(servF, buff3, _IOFBF, DISK_BUFFER_SIZE);// fully buffered
	fprintf(servF, "HOST\t\tIP\t\tService\n");

}

void openSpecServiceFile() {
	specServF = fopen(RESULTS4_FILE, "w");
	if (specServF == NULL) {
		printf("Error opening file!\n");
		exit(1);
	}
	setvbuf(specServF, buff4, _IOFBF, DISK_BUFFER_SIZE);// fully buffered
	fprintf(specServF, "HOST\t\tIP\t\tService\n");

}

void openStatsFile() {
	statsFile = fopen(STATS_FILE, "w");
	if (statsFile == NULL) {
		printf("Error opening file!\n");
		exit(1);
	}
	setvbuf(statsFile, buff5, _IOFBF, 1);// non-buffered
}

void persistSyn(char *ip, int port) {
	fprintf(synF, "%s:%d\n", ip, port);
}

void persistClosedSyn(char *ip, int port) {
	fprintf(synF, "%s:%d Closed\n", ip, port);
}


void persistAck(char *ip, int port, char *msg) {
	deblank(msg);
	fprintf(ackF, "{host{%s} port{%d} sent {%s}}\n", ip, port, msg);
}

void persistServ(char *ip, int port, char *msg) {
	fprintf(servF, "%s\t\t%d\t%s\n", ip, port, msg);
}

void persistSpecialServ(char *ip, int port, char *msg) {
	fprintf(specServF, "%s\t\t%d\t%s\n", ip, port, msg);
}


void closeSpecialServFile() {
	if (specServF != NULL)
		fclose(specServF);
}

void closeServFile() {
	if (servF != NULL)
		fclose(servF);
}

void closeSynFile() {
	if (synF != NULL)
		fclose(synF);
}

void closeAckFile() {
	if (ackF != NULL)
		fclose(ackF);
}
