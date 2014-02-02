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
#include "../../conf.h"

#define CPE_FILE "src/plugin/VulnScanner/official-cpe-dictionary_v2.3.xml"

void loadCpeFile() {
	FILE *fp;
	long lSize;
	char *buffer;

	fp = fopen( CPE_FILE, "rb");
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

	/*  whole text */
	printf("file loaded\n");
	cpePairs = malloc(sizeof(struct CpeP*) * 900000000); /* allocate memory*/
	unsigned long long int *cpes = 0;

	matchTitle(buffer, cpePairs, cpes, strlen(buffer));
	printf("found %d capes\n ", cpes);
	free (cpePairs); /* free the memory for the pointer to pointers */

	fclose(fp);
	free(buffer);
}

struct plugIn *initInput() {
	struct plugIn *pn = malloc(sizeof(unsigned int) * 2);
	pn->ports[0] = 80;
	pn->ports[1] = 0;
	return pn;
}

struct plugIn *onInitPlugin() {
	//struct plugIn *pugIn = initInput();
	initRegex();
	openServiceFile();
	openSpecServiceFile();
	loadCpeFile();
	return initInput();
}

void onStopPlugin() {
	closeServFile();
	closeSpecialServFile();
}

void getServiceInput(int port, char *msg) {
	strncpy(msg, "GET / HTTP/1.0\r\nConnection: close\r\n\r\n", 80);
}

char *getCPE() {
	return "";
}

void provideOutput(char *host, int port, char *msg) {
	if (synOnly == TRUE) {
		return;
	}
	//get server banner
	char *serv = match(msg);
	persistServ(host, port, serv);
	printf("Analyzing [%s]\n", serv);
	//get cpe
	char *cpebanner = getCPE(serv);
	printf("Found CPE [%s] corresponding to [%s]\n", cpebanner, serv);

	if (serv != NULL) {
		free(serv);
	}
}
