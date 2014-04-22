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


void initRegex() {
	int i = 0;
	int reti;
	int size = sizeof(http_serv_str) / sizeof(http_serv_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&http_serv_matcher[i], http_serv_str[i][0], REG_ICASE);
		if (reti) {
			perror("Could not compile regex\n");
			exit(0);
		}
	}
	size = sizeof(http_info_str) / sizeof(http_info_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&http_info_matcher[i], http_info_str[i][0], REG_EXTENDED);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(ssh_serv_str) / sizeof(ssh_serv_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&ssh_serv_matcher[i], ssh_serv_str[i][0], REG_ICASE);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(ssh_info_str) / sizeof(ssh_info_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&ssh_info_matcher[i], ssh_info_str[i][0], REG_EXTENDED);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(ftp_serv_str) / sizeof(ftp_serv_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&ftp_serv_matcher[i], ftp_serv_str[i][0], REG_ICASE);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(ftp_info_str) / sizeof(ftp_info_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&ftp_info_matcher[i], ftp_info_str[i][0], REG_ICASE);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(smtp_serv_str) / sizeof(smtp_serv_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&smtp_serv_matcher[i], smtp_serv_str[i][0], REG_ICASE);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(smtp_info_str) / sizeof(smtp_info_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&smtp_info_matcher[i], smtp_info_str[i][0], REG_ICASE);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(telnet_info_str) / sizeof(telnet_info_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&telnet_info_matcher[i], telnet_info_str[i][0], REG_ICASE);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(telnet_serv_str) / sizeof(telnet_serv_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&telnet_serv_matcher[i], telnet_serv_str[i][0], REG_ICASE);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(osRegexStr) / sizeof(osRegexStr[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&osRegex[i], osRegexStr[i][0], REG_ICASE);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(cam_serv_str) / sizeof(cam_serv_str[0]);
	for (i = 0; i < size; i++) {
		reti = regcomp(&cam_serv_matcher[i], cam_serv_str[i][0], REG_ICASE);
		if (reti) {
			perror("Could not compile regex\n");
			exit(1);
		}
	}
	size = sizeof(print_serv_str) / sizeof(print_serv_str[0]);
		for (i = 0; i < size; i++) {
			reti = regcomp(&print_serv_matcher[i], print_serv_str[i][0], REG_ICASE);
			if (reti) {
				perror("Could not compile regex\n");
				exit(1);
			}
		}
	
}

int carryOutServMatch(char *in, char *out, const char *regexStrs[][2], const regex_t regexM[], int size) {
	int i = 0, reti;
	int known = FALSE;
	for (i = 0; i < size; i++) {
		reti = regexec(&(regexM[i]), in, 0, NULL, 0);
		if (!reti) {
			//printf("Matched, service seeems [[%s]], to service %s getting more info...\n\n", regexStrs[i][1],in);
			known = TRUE;
			strncpy(out, regexStrs[i][1], 200);
			return known;
		}
	}
	return known;
}
int carryOutInfoMatch(char *in, char *out, const char *regexStrs[][2], const regex_t regexM[], int size) {
	int i = 0, reti;
	int known = FALSE;
	for (i = 0; i < size; i++) {
		reti = regexec(&(regexM[i]), in, 0, NULL, 0);
		if (!reti) {
			//printf("Matched, service seeems [[%s]], to service %s getting more info...\n\n", regexStrs[i][1],in);
			strcat(out, regexStrs[i][1]);
			known = TRUE;
			//printf("%s\n", out);
		}
	}
	return known;
}
int carryOutAdvancedInfoMatch(char *in,  char *out, const char *regexStrs[][2],  const regex_t regexM[], int size) {
	int i = 0, reti;
	int known = FALSE;
	for (i = 0; i < size; i++) {
		reti = regexec(&(regexM[i]), in, maxGroups, groupArray, 0);
		if (!reti) {
			if (i < 2 && groupArray[1].rm_so != (size_t) - 1 && groupArray[1].rm_eo - groupArray[1].rm_so > 4) {
				char sourceCopy[strlen(in) + 1];
				strncpy(sourceCopy, in, strlen(in) + 1);
				sourceCopy[groupArray[1].rm_eo] = 0;
				strcat(out, " (");
				strncat(out, sourceCopy + groupArray[1].rm_so, 50);
				strcat(out, ")");
				known = TRUE;
				return known;
			} else if (i > 1) {
				//printf("Matched, service seeems [[%s]], to service %s getting more info...\n\n", regexStrs[i][1],in);
				strncat(out, regexStrs[i][1], 200 - (strlen(out) +1));
				known = TRUE;
				return known;
			}
		}
	}
	return known;
}

char **tokenize(char *in) {
	char **out = (char**) calloc(50, sizeof(char*));
	unsigned int i=4, j=0, k=0, l;
	l = strlen(in);
	while (i < l) {
		//go to the next separator token
		while (i < l && in[i] != tokens[6] && in[i] != tokens[7] && in[i] != tokens[0] && in[i] != tokens[1]
		       && in[i] != tokens[2] && in[i] != tokens[3]&& in[i] != tokens[4] && in[i] != tokens[5]) {i++;}
		if (i-j > 1) {
			//copy mem
			out[k] = (char*) calloc(i-j+1, sizeof(char));
			memcpy(out[k], &in[j], i-j);
			char *curr = out[k];
			curr[i-j] = '\0';
		}
		//inc indexed
		j = i + 1;
		k++;
		i++;
	}
	//test
	for (i = 0; i < k; i++) {
		//printf("[%s] ", out[i]);
	}
	//printf("\n");
	return out;
}

char *matchBanner(char *in) {
	char *out = NULL;
	int totLen = strlen(in);
	int i = 0, j = 0;
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
	}else {
		i=0;
		//matches Basic realm=\"
		while ((i + 6) < totLen && (in[i] != 'r' || in[i + 1] != 'e' || in[i + 2] != 'a' || in[i + 3] != 'l' || in[i + 4] != 'm' || in[i + 5] != '=' || in[i + 6] != '"')) {i++;}
		j=i+7;
		i+=8;
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

char *matchService(char *in)
{
	char *out= malloc(sizeof(char) * 200);
	int known = carryOutServMatch(in, out, cam_serv_str, cam_serv_matcher, camServSize);
	if (known == TRUE) {
		return out;
	}
	known = carryOutServMatch(in, out, print_serv_str, print_serv_matcher, printServSize);
	if (known == TRUE) {
		return out;
	}
	known = carryOutServMatch(in, out, http_serv_str, http_serv_matcher, httpServSize);
	if (known == TRUE) {
		carryOutAdvancedInfoMatch(in, out, http_info_str, http_info_matcher, httpInfoSize);
		return out;
	}
	known = carryOutServMatch(in, out, ssh_serv_str, ssh_serv_matcher, sshServSize);
	if (known == TRUE) {
		strcat(out, "-");
		carryOutAdvancedInfoMatch(in, out, ssh_info_str, ssh_info_matcher, sshInfoSize);
		return out;
	}
	known = carryOutServMatch(in, out, ftp_serv_str, ftp_serv_matcher, ftpServSize);
	if (known == TRUE) {
		carryOutInfoMatch(in, out, ftp_info_str, ftp_info_matcher, ftpInfoSize);
		return out;
	}
	known = carryOutServMatch(in, out, smtp_serv_str, smtp_serv_matcher, smtpServSize);
	if (known == TRUE) {
		carryOutInfoMatch(in, out, smtp_info_str, smtp_info_matcher, smtpInfoSize);
		return out;
	}
	known = carryOutServMatch(in, out, telnet_serv_str, telnet_serv_matcher, telnetServSize);
	if (known == TRUE) {
		carryOutInfoMatch(in, out, telnet_info_str, telnet_info_matcher, telnetInfoSize);
		return out;
	}
	strncpy(out, UNKNOWN, 200);
	return out;
}


char *matchSpecial(char *in)
{
	char *out= malloc(sizeof(char) * 200);
	int known = carryOutServMatch(in, out, cam_serv_str, cam_serv_matcher, camServSize);
	if (known == TRUE) {
		return out;
	}
	known = carryOutServMatch(in, out, print_serv_str, print_serv_matcher, printServSize);
	if (known == TRUE) {
		return out;
	}
	strncpy(out, UNKNOWN, 200);
	return out;
}

char *match(char *in) {
	char *out = matchService(in);
	if(strcmp(out, UNKNOWN) != 0) {
		int i;
		for (i = 0; i < osSize; i++) {
			//printf("matching %s\n\n", regexStrs[i][0]);
			int reti = regexec(&(osRegex[i]), in, 0, NULL, 0);
			if (!reti) {
				//printf("More Info %s\n\n\n", regexStrs[i][1]);
				strncat(out, osRegexStr[i][1], 200 - (strlen(out) +1));
				return out;
			}
		}
	}
	return out;
}
