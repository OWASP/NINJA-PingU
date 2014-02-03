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

//Allocate CPE key value pairs
struct CpeP {
	char *title;
	char *cpe;
};

//Allocate NVD key value pairs
struct NVD_S {
	char *cve;
	char *vulns;
};

// pointer of NVD pairs pointers
struct NVD_S **nvdPairs;

// pointer of CPE pairs pointers
struct CpeP **cpePairs;

void initRegex() {
	int i = 0;
	int reti;
	int size = sizeof(http_info_str) / sizeof(http_info_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&http_info_matcher[i], http_info_str[i][0], REG_EXTENDED);
		if (reti) { perror("Could not compile regex\n"); exit(1); 
	}
}

	//compile CPE related regexes
	reti = regcomp(&title_cpe_matcher, title_cpe_regex, REG_EXTENDED);
	if (reti) {	perror("Could not compile regex\n"); exit(1); }
	reti = regcomp(&str_cpe_matcher, str_cpe_regex, REG_EXTENDED);
	if (reti) {perror("Could not compile regex\n"); exit(1); }
	
	//compile NVD related regexes
	reti = regcomp(&nvd_entry_matcher, nvd_entry_regex, REG_EXTENDED);
	if (reti) {	perror("Could not compile regex\n"); exit(1); }
	reti = regcomp(&nvd_cve_matcher, nvd_cve_regex, REG_EXTENDED);
	if (reti) {perror("Could not compile regex\n"); exit(1); }
	reti = regcomp(&nvd_cpe_matcher, nvd_cpe_regex, REG_EXTENDED);
	if (reti) {perror("Could not compile regex\n"); exit(1); }

}
int carryOutServMatch(char *in, char *out, const char *regexStrs[][2], const regex_t regexM[], int size) {
	int i = 0, reti;
	for (i = 0; i < size; i++) {
		reti = regexec(&(regexM[i]), in, 0, NULL, 0);
		if (!reti) {
			//printf("Matched, service seeems [[%s]], to service %s getting more info...\n\n", regexStrs[i][1],in);
			strncpy(out, regexStrs[i][1], 200);
		}
	}
	return 1;
}

int carryOutAdvancedInfoMatch(char *in, char *out, const char *regexStrs[][2], const regex_t regexM[], int size) {
	int i = 0, reti;
	int known = FALSE;
	for (i = 0; i < size; i++) {
		reti = regexec(&(regexM[i]), in, maxGroups, groupArray, 0);
		if (!reti) {
			if (i < 2 && groupArray[1].rm_so != (size_t) - 1 && groupArray[1].rm_eo - groupArray[1].rm_so > 4) {
				char sourceCopy[strlen(in) + 1];
				strncpy(sourceCopy, in, strlen(in) + 1);
				sourceCopy[groupArray[1].rm_eo] = 0;
				strncat(out, sourceCopy + groupArray[1].rm_so, 50);
				known = TRUE;
				return known;
			} else if (i > 1) {
				printf("Matched, service seeems [[%s]], to service %s getting more info...\n\n", regexStrs[i][1], in);
				strncat(out, regexStrs[i][1], 200 - (strlen(out) + 1));
				known = TRUE;
				return known;
			}
		}
	}
	return known;
}

char *matchService(char *in) {
	char *out = malloc(sizeof(char) * 200);
	carryOutAdvancedInfoMatch(in, out, http_info_str, http_info_matcher, httpInfoSize);
	return out;
}

char *match(char *in) {
	char *out = matchService(in);
	return out;
}

unsigned long long int parseCPE(char *in) {
	unsigned long long int index = 0;
	unsigned long long int i = 0;
	unsigned long long int j = 0;
	int reti;
	int matchLen;
	int maxLen = strlen(in);
	//while file not parsed
	while (maxLen -i > 5000) {
		//allocate mem for the struct to hold the key value pair
		struct CpeP *curr = malloc(sizeof(char *) * 2);

	
		//finds the next <cpe-item name="cpe:/a:1024cms:1024_cms:1.3.1">
		while (in[i] != '<' || in[i+1] != 'c' || in[i+5] != 'i' || in[i+10] != 'n' || in[i+15] != '"'){ i++; printf("oooo%llu, %c\n", i, in[i]);}
		i=i+16;j = i;
		
		//looks for the other quotes
		while (in[i] != '"'){ i++; }
		
		//copies the data
		curr->title = malloc(sizeof(char *) * i-j);
		strncpy(curr->title, in + j, i - j);
		curr->title[j-i] = 0;
		printf("title %s\n", curr->title);

		//finds the next title xml:lang="en-US">2Glux Sexy Polling (com_sexypolling) component for Joomla! 0.9.4</title>
		while (in[i] != '<' || in[i+1] != 't' || in[i+7] != 'x' || in[i+11] != 'l' || in[i+15] != '=' || in[i+17] != 'e'  ){ i++;}
		i= i + 24; j = i;
	
		//looks for the other quotes
		while (in[i] != '<'){ i++;}
		
		//copies the data
		curr->cpe = malloc(sizeof(char *) * i-j);
		strncpy(curr->cpe, in + j, i - j);
		curr->cpe[j-i] = 0;
		printf("cpe %s\n", curr->cpe);
		i++;
		index++;
	}
	return index;
}

unsigned long long int parseNVD(char *in) {
	unsigned long long int index = 0;
	unsigned long long int i = 1;
	unsigned long long int j = 1;
		
	int reti;
	int entryLen, cveLen, cpeLen;
	int totLen = strlen(in);
	//while file not parsed
	while (totLen- i > 500) {
		//allocate mem for the struct to hold the key value pair
		struct NVD_S *curr = malloc(sizeof(char *) * 2);

		//find next entry start
		while (in[i] != '<' || in[i+1] != 'e' || in[i+2] != 'n' || in[i+3] != 't' || in[i+4] != 'r' || in[i+5] != 'y'){ i++; }
		
		//find the open quotes tag for the cve
		while (in[i] != '"'){ i++; }
		
		//the index is in the cve copy the content until quotes
		 i++; j = i;
		while (in[i] != '"'){ i++; }
		
		curr->cve = malloc(sizeof(char *) * i-j);
		strncpy(curr->cve, in+j, i-j);
		curr->cve[j-i] = 0;

		//find <vuln:vulnerable-software-list>
		while (in[i] != '<' || in[i+1] != 'v'|| in[i+17] != 's' || in[i+26] != 'l' ){ i++;}
		 i++;j = i;

		//find </vuln:vulnerable-software-list>
		while (in[i] != '<' || in[i+1] != '/' || in[i+18] != 's' ) {i++;}

		curr->vulns = malloc(sizeof(char) * i-j);
		strncpy(curr->vulns, in+j, i-j);
		curr->vulns[j-i] = 0;
		//printf("found i %llu j %llu vulns %s\n", i, j, curr->vulns);
		i++;
		index++;
	}
	return index;
}
