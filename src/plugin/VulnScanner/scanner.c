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

#include <string.h>
#include <stdlib.h>

#include "matcher.c"

void traverseCPE() {
	unsigned int k;
	struct List *cvwe;
	for (k = 6000; k < cpelen; k++) {
		cvwe = cpePairs[k]->cve;
		//printf("cpe[%s] title[%s]\n", cpePairs[k]->cpe, cpePairs[k]->title);
		while (cvwe != NULL && cvwe->next != NULL) {
			printf("in the inner looop\n");
			if (cvwe->cve != NULL && strlen(cvwe->cve) > 6) {
				printf("Found %s\n", cvwe->cve);
			}
			if (cvwe == NULL || cvwe->next == NULL) {
				break;
			}
			cvwe = cvwe->next;
		}
	}
}
char *loadFile(char *file) {
	FILE *fp;
	long lSize;
	char *buffer;

	fp = fopen(file, "rb");
	if (!fp)
		perror("Could Not Read File"), exit(1);

	fseek(fp, 0L, SEEK_END);
	lSize = ftell(fp);
	rewind(fp);

	/* allocate memory for entire content */
	buffer = calloc(1, lSize + 1);
	if (!buffer)
		fclose (fp), fputs("memory alloc fails", stderr), exit(1);

	/* copy the file into the buffer */
	if (1 != fread(buffer, lSize, 1, fp))
		fclose (fp), free(buffer), fputs("entire read fails", stderr), exit(1);

	fclose(fp);
	return buffer;
}

struct plugIn *initInput() {
	struct plugIn *pn = malloc(sizeof(unsigned int) * 2);
	pn->ports[0] = 80;
	pn->ports[1] = 0;
	return pn;
}

struct plugIn *onInitPlugin() {
	//struct plugIn *pugIn = initInput();
	openServiceFile();
	openSpecServiceFile();

	//load CPE file
	char *cpefile = loadFile(CPE_FILE);

	//variable to hold the CPE pairs
	cpePairs = malloc(sizeof(struct CPE_DATA *));

	cpelen = parseCPE(cpefile);
	printf("\t+Internalized CPE Entries\t\t[%u]\n ", cpelen);
	free(cpefile);

	//load NVD file
	char *nvdfile = loadFile(NVD_FILE);

	//variable to hold the NVD data
	nvdPairs = malloc(sizeof(struct NVD_S *));

	nvdlen = parseNVD(nvdfile);
	printf("\r\t+Merged NVD Entries\t\t[%llu]\n ", nvdlen);

	//for each cpe
	void traverseCPE();
	return initInput();
}

void onStopPlugin() {
	closeServFile();
	closeSpecialServFile();
}

void getServiceInput(int port, char *msg) {
	strncpy(msg, "GET / HTTP/1.0\r\nConnection: close\r\n\r\n", 80);
}


void provideOutput(char *host, int port, char *msg) {
	if (synOnly == TRUE) {
		return;
	}
	//get server banner
	char *serv = matchService(msg);
	if (serv == NULL || strlen(serv) < 4) {
		return;
	}
	persistServ(host, port, serv);
	//printf("Analyzing [%s]\n", serv);
	char **serv_parsed = tokenize(serv);
	//printf("Token [%s]\n", serv);
	//get cpe
	struct CPE_DATA **banners = getCPE(serv_parsed);
//	printf("Found CPE [%s] corresponding to [%s]\n", banner->cpe, serv);
	int l = 0;
	while(banners[l] != NULL && banners[l]->cpe != NULL) {
		struct List *nList = banners[l]->cve;
		persistSpecialServ(serv, port, banners[l]->cpe);
		while (nList != NULL && nList->cve != NULL) {
				persistSpecialServ("", 0, nList->cve);
				nList = nList->next;
			}
		
		free(banners[l]);
		l++;
	}
	if(banners != NULL) {
		free(banners);
	}
	if (serv != NULL) {
		free(serv);
	}



	
}
