/*   OWASP NINJA PingU: Is Not Just a Ping Utility
 *
 *  Copyright (C) 2014 Guifre Ruiz <guifre.ruiz@owasp.org>
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
#include <regex.h>
#include <string.h>
#include <strings.h>

#include "matcher.h"
#include "../../pers.c"

char **tokenize(char *in) {
	char **out = (char**) calloc(100, sizeof(char*));
	unsigned int i=4, j=0, k=0, l;
	l = strlen(in);
	while (i < l) {
		//go to the next separator token
		while (i < l && in[i] != tokens[6] && in[i] != tokens[7] && in[i] != tokens[0] && in[i] != tokens[1]
		       && in[i] != tokens[2] && in[i] != tokens[3]&& in[i] != tokens[4] && in[i] != tokens[5]) {i++;}
		if (i-j < 2){j = i + 1;i++; continue;}
		//copy mem
		out[k] = (char*) calloc(i-j+1, sizeof(char));
		memcpy(out[k], &in[j], i-j);
		char *curr = out[k];
		curr[i-j] = '\0';
		//inc indexed
		j = i + 1;
		k++;
		i++;
	}
	//test
//	for (i = 0; i < k; i++) {
//		printf("[%s] ", out[i]);
//	}
//	printf("\n sizeof(%d) strlen(%d)", sizeof(out), strlen(out));

	return out;
}

struct CPE_DATA **getCPE(char **in) {
	struct CPE_DATA **cpeRes = malloc(sizeof(struct CPE_DATA *)*20);
	unsigned int len = cpelen;
	unsigned int inLen = 0;
	unsigned int i=0, j, k,m=0, res=0, best=0, bestI= 0;
	while (in[i] != NULL){
		inLen++;
		printf("[%s]", in[i]);
		i++;
	}printf("\n");
	i=0;
	//for each CPE structure
	for (j = 6000; j < len-1000; j++) {
		//foreach token in the server banner
		while (in[i] != NULL && cpePairs[j]->title != NULL) {
			k=0; char **titleTokens = cpePairs[j]->title;
			//for each token in the title and each token in the banner
			while (titleTokens[k] != NULL) {
				//printf("Comparing [%s] and [%s]\n", titleTokens[k],  in[i]);
				if (strcasecmp(titleTokens[k], in[i]) == 0) {
					res++;
					//printf("[%s] equal [%s]\n", titleTokens[k], in[i]);
				}
				k++;
			}
			i++;
		}
		
		if (res >i/2 && i > 2) {
			i=0;while (in[i] != NULL){
					inLen++;
					printf("[%s]", in[i]);
					i++;
				}
			cpeRes[m]=malloc(sizeof(struct CPE_DATA *));
			cpeRes[m]=cpePairs[j];
			m++;
			printf("\n");
		}
		//see if the result is best so far
//		if (res >= best) {
//			best = res;
//			bestI=j;
//		}
		//reset counters
		res = 0;
		i=0;
	}
	//printf("[%s] matched [%s]\n", in[0], cpePairs[bestI]->title[0]);
	return cpeRes;//cpePairs[bestI];
}

char *matchService(char *in) {
	char *out = NULL;
	int totLen = strlen(in);
	int i = 0, j=0;
	//matches Server:
	while ((i + 6) < totLen && (in[i] != 'S' || in[i + 1] != 'e' || in[i + 2] != 'r' || in[i + 3] != 'v' || in[i + 4] != 'e' || in[i + 5] != 'r' || in[i + 6] != ':')) {i++;}
	i += 8;
	if (i < totLen) {
		j = i;
		//matches new line
		while (in[i] != 10 && in[i] != '\r' && i < totLen) {i++;}
		out = malloc(sizeof(char *) * ((i - j) + 1));
		strncpy(out, in + j, i - j);
		out[i - j] = '\0';
	} else {
		i=0;
		//matches Basic realm=\"
		while ((i + 6) < totLen && (in[i] != 'r' || in[i + 1] != 'e' || in[i + 2] != 'a' || in[i + 3] != 'l' || in[i + 4] != 'm' || in[i + 5] != '=' || in[i + 6] != '"')) {i++;}
		j=i++;
		//matches the double quote
		while (i<totLen && in[i] != '"'){i++;} 
		if (i < totLen) {
			out = (char*) calloc(i-j+1, sizeof(char));
			memcpy(out, &in[j], i-j);
			out[i-j] = '\0';
		}
	}
	return out;
}

unsigned long long int parseCPE(char *in) {
	unsigned int index = 0;
	unsigned int i = 1;
	unsigned int j = 1;
	int maxLen = strlen(in);
	//while file not parsed
	while (maxLen - i > 1000) {
		//allocate mem for the struct to hold the key value pair
		cpePairs[index] = malloc(sizeof(struct CPE_DATA *));

		//finds the next <cpe-item name="cpe:/a:1024cms:1024_cms:1.3.1">
		while (in[i] != '<' || in[i + 1] != 'c' || in[i + 5] != 'i' || in[i + 10] != 'n' || in[i + 15] != '"') {i++;}
		i = i + 16;j = i;

		//looks for the other quotes
		while (in[i] != '"') {i++;}

		//copies the data
		cpePairs[index]->cpe = (char*) calloc(i-j+1, sizeof(char));
		memcpy(cpePairs[index]->cpe, &in[j], i-j);
		cpePairs[index]->cpe[i - j] = '\0';

		//finds the next title xml:lang="en-US">2Glux Sexy Polling (com_sexypolling) component for Joomla! 0.9.4</title>
		while (in[i] != '<' || in[i + 1] != 't' || in[i + 7] != 'x' || in[i + 11] != 'l' || in[i + 15] != '=' || in[i + 17] != 'e') {i++;}
		i = i + 24;j = i;

		//looks for the other quotes
		while (in[i] != '<') {i++;}
		
		//copies the data
		char *tempT = (char*) calloc(i-j+1, sizeof(char));
		memcpy(tempT, &in[j], i-j);
		tempT[i - j] = '\0';
		//printf("i[%d] cpe [%s] title {%s} \n", index, cpePairs[index]->cpe, tempT);
		cpePairs[index]->title = tokenize(cpePairs[index]->cpe);//TODO Posar el cve enlloc de tmp

		index++;
	}
	return index;
}

unsigned long long int parseNVD(char *in) {
	unsigned int index = 0;
	unsigned int i = 0;
	unsigned int j = 0;
	int totLen = strlen(in);

	//while file not parsed
	while (totLen - i > 3000) {
		//allocate mem for the struct to hold the key value pair
		nvdPairs[index] = malloc(sizeof(struct NVD_DATA *));

		//find next entry start
		while (in[i] != '<' || in[i + 1] != 'e' || in[i + 2] != 'n' || in[i + 3] != 't' || in[i + 4] != 'r'	|| in[i + 5] != 'y') {	i++;}

		//find the open quotes tag for the cve
		while (in[i] != '"') {i++;}

		//the index is in the cve copy the content until quotes
		i++; j = i;
		while (in[i] != '"') {i++;}

		nvdPairs[index]->cve = malloc(sizeof(char *) * (i - j) + 1);
		memcpy(nvdPairs[index]->cve, &in[j], i-j);

		nvdPairs[index]->cve[i - j] = '\0';

		//find <vuln:vulnerable-software-list>
		while (in[i] != '<' || in[i + 1] != 'v' || in[i + 17] != 's' || in[i + 26] != 'l') {i++;}
		i++; j = i;

		//find </vuln:vulnerable-software-list>
		while (in[i] != '<' || in[i + 1] != '/' || in[i + 18] != 's' || in[i + 27] != 'l') {i++;}

		nvdPairs[index]->vulns = malloc(sizeof(char *) * (i - j) + 1);
		memcpy(nvdPairs[index]->vulns, &in[j], i-j);
		nvdPairs[index]->vulns[i - j] = '\0';
		//printf("found i [%llu] j [%llu] vulns [%s]\n", i, j, nvdPairs[index]->vulns);

		unsigned int k;
		//for each cpe
		for (k = 0; k < cpelen; k++) {
			//printf("cpe[%s] title[%s]\n", cpePairs[k]->cpe, cpePairs[k]->title);

			if (cpePairs[k] != NULL && cpePairs[k]->cpe != NULL && strlen(cpePairs[k]->cpe) > 6)
				//if the cpe is in the vuln ones of the nvd
				if (strstr(nvdPairs[index]->vulns, cpePairs[k]->cpe) != NULL) {
					//printf("Matched[%s] [%s]\n", cpePairs[k]->cpe, cpePairs[k]->title);
					//create a new data to hold the cvw
					struct List *nList = malloc(sizeof(struct List *));
					nList->cve =  (char*) calloc(strlen(nvdPairs[index]->cve), sizeof(char));
					//copy the value
					strncpy(nList->cve, nvdPairs[index]->cve, strlen(nvdPairs[index]->cve));
					
					nList->cve[strlen(nvdPairs[index]->cve)] = '\0';
					//printf("Copied %s\n", nList->cve);

					//add to the list
					nList->next = malloc(sizeof(struct List *));
					nList->next = cpePairs[k]->cve;
					cpePairs[k]->cve = nList;
				}
		}
		i++;
		index++;
	}
	return index;
}
