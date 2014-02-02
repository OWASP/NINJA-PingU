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

// pointer of cpepair pointers
struct CpeP **cpePairs;

void initRegex() {
	int i = 0;
	int reti;
	int size = sizeof(http_info_str) / sizeof(http_info_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&http_info_matcher[i], http_info_str[i][0], REG_EXTENDED); //needed for capturing groups
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}

	reti = regcomp(&title_cpe_matcher, title_cpe_regex, REG_EXTENDED); //needed for capturing groups
	if (reti) {
		perror("Could not compile regex\n");
		exit(1);
	}
	reti = regcomp(&str_cpe_matcher, str_cpe_regex, REG_EXTENDED); //needed for capturing groups
	if (reti) {
		perror("Could not compile regex\n");
		exit(1);
	}
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

void matchTitle(char *in, struct CpeP **cpePairs, unsigned long long int *ind, int len) {
	int reti, i;
	int known = FALSE;
	int matchLen;
	//while file not parsed
	while (strlen(in) > 100) {
		//allocate mem for the struct to hold the key value pair
		struct CpeP *curr = malloc(sizeof(char *) * 2);
		
		//find the following title
		reti = regexec(&(title_cpe_matcher), in, maxGroups, groupArray, 0);
		if (!reti) {
			//computes length title
			matchLen = groupArray[1].rm_eo - groupArray[1].rm_so;
			
			//allocates mem to store the title
			curr->title = malloc(sizeof(char *) * matchLen);
			
			//stores the title
			strncpy(curr->title, in + groupArray[1].rm_so, matchLen);
			curr->title[matchLen] = 0;
			//printf("title {%s} ", curr->title);
			
			//seeks the cpe id
			reti = regexec(&(str_cpe_matcher), in, maxGroups, groupArray2, 0);
			if (!reti) {
				//length of the cpe id
				matchLen = groupArray2[1].rm_eo - groupArray2[1].rm_so;
				//allocates mem for holding it
				curr->cpe = malloc(sizeof(char *) * matchLen);
				//copies it 
				strncpy(curr->cpe, in + groupArray2[1].rm_so, matchLen);
				curr->cpe[matchLen] = 0;
				//printf("cpe {%s}\n", curr->cpe);

				//increment pointers
				int t = ind;
				cpePairs[t] = curr;
				in = in + groupArray2[1].rm_eo;
				printf("%d strlen(%d) ind %d", ind, strlen(in), ind);
				ind++;
				len = len -i;
			} else {
				break;
			}
		} else {
			break;
		}
	}
}
