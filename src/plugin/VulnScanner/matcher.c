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

#include "matcher.h"
#include "../../pers.c"


char *matchService(char *in) {
	char *out = NULL;
	int totLen = strlen(in);
	int i = 0;
	while ( (i+6) < totLen && (in[i] != 'S' || in[i+1] != 'e'  || in[i+2] != 'r'  || in[i+3] != 'v'  || in[i+4] != 'e'  || in[i+5] != 'r' || in[i+6] != ':')) {
		i++;
	}
	if (i < totLen) {
		i = i+8;
		int j = i;
		while(in[i] != 10 && in[i] != '\r' && i < totLen) {
			i++;
		}
		out = malloc(sizeof(char *) * (i-j));
		strncpy(out, in+j, i-j);
		out[i-j]=0;
	}
	return out;
}

unsigned long long int parseCPE(char *in) {
	unsigned int index = 0;
	unsigned int i = 0;
	unsigned int j = 0;
	int maxLen = strlen(in);
	//while file not parsed
	while (maxLen -i > 1000) {
		//allocate mem for the struct to hold the key value pair
		cpePairs[index]=malloc(sizeof(struct CPE_DATA *));
		
		//finds the next <cpe-item name="cpe:/a:1024cms:1024_cms:1.3.1">
		while (in[i] != '<' || in[i+1] != 'c' || in[i+5] != 'i' || in[i+10] != 'n' || in[i+15] != '"'){ i++;}
		i=i+16;j = i;
		
		//looks for the other quotes
		while (in[i] != '"'){ i++;}
		
		//copies the data
		cpePairs[index]->cpe = malloc(sizeof(char *) * (i-j)+1);
		strncpy(cpePairs[index]->cpe, in + j, i - j);
		cpePairs[index]->cpe[i-j] = '\0';
		
		//finds the next title xml:lang="en-US">2Glux Sexy Polling (com_sexypolling) component for Joomla! 0.9.4</title>
		while (in[i] != '<' || in[i+1] != 't' || in[i+7] != 'x' || in[i+11] != 'l' || in[i+15] != '=' || in[i+17] != 'e'  ){ i++;}
		i= i + 24; j = i;
		
		//looks for the other quotes
		while (in[i] != '<'){ i++;}
		
		//copies the data
		cpePairs[index]->title = malloc(sizeof(char *) * (i-j)+1);
		strncpy(cpePairs[index]->title, in + j, i - j);
		cpePairs[index]->title[i-j] = '\0';
		//printf("i[%d] cpe [%s] title {%s} \n", index, cpePairs[index]->cpe, cpePairs[index]->title);
		
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
		while (in[i] != '<' || in[i+1] != 'e' || in[i+2] != 'n' || in[i+3] != 't' || in[i+4] != 'r' || in[i+5] != 'y'){ i++; }
		
		//find the open quotes tag for the cve
		while (in[i] != '"'){ i++; }
		
		//the index is in the cve copy the content until quotes
		i++; j = i;
		while (in[i] != '"'){ i++; }
		
		nvdPairs[index]->cve = malloc(sizeof(char *) * (i-j)+1);
		strncpy(nvdPairs[index]->cve, in+j, i-j);
		nvdPairs[index]->cve[i-j] = '\0';
		
		//find <vuln:vulnerable-software-list>
		while (in[i] != '<' || in[i+1] != 'v'|| in[i+17] != 's' || in[i+26] != 'l' ){ i++;}
		 i++;j = i;
		
		//find </vuln:vulnerable-software-list>
		while (in[i] != '<' || in[i+1] != '/' || in[i+18] != 's' || in[i+27] != 'l') {i++;}
		
		nvdPairs[index]->vulns = malloc(sizeof(char *) * ( i-j)+1);
		strncpy(nvdPairs[index]->vulns, in+j, i-j);
		nvdPairs[index]->vulns[i-j] = '\0';
		//printf("found i [%llu] j [%llu] vulns [%s]\n", i, j, nvdPairs[index]->vulns);
		
		unsigned int k;
		//for each cpe
		for (k=0; k < cpelen; k++) {
			//printf("cpe[%s] title[%s]\n", cpePairs[k]->cpe, cpePairs[k]->title);
			
			if (cpePairs[k] != NULL && cpePairs[k]->cpe != NULL && strlen(cpePairs[k]->cpe) > 6)				
				//if the cpe is in the vuln ones of the nvd
				if(strstr(nvdPairs[index]->vulns, cpePairs[k]->cpe) != NULL) {
				 //printf("Matched[%s] [%s]\n", cpePairs[k]->cpe, cpePairs[k]->title);
					//create a new data to hold the cvw
					struct List *nList = malloc(sizeof(struct List *));
					nList->cve=malloc(sizeof(char)*strlen(nvdPairs[index]->cve));
					
					//copy the value
					strncpy(nList->cve, nvdPairs[index]->cve, strlen(nvdPairs[index]->cve));
					nList->cve[strlen(nvdPairs[index]->cve)]='\0';
					//printf("Copied %s\n", nList->cve);
					
					//add to the list
					nList->next= malloc(sizeof(struct List *)+sizeof(char)*30);
					nList->next = cpePairs[k]->cve;
					cpePairs[k]->cve = nList;
				}
		}
		i++;
		index++;
	}
	return index;
}
