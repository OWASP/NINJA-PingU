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
#include "matcher.c"

void onInitPlugin() {
	initRegex();
	openServiceFile();
	openSpecServiceFile();
}

void onStopPlugin() {
	closeServFile();
	closeSpecialServFile();
}

void getServiceInput(int port, char *msg) {
	switch (port) {
	case 25:
		strncpy(msg, "ehlo ffff\r\nquit\r\n", 80);
		break;
	case 21:
		strncpy(msg, "HELP\r\nQUIT\r\n\r\n", 80);
		break;
	case 80:
		strncpy(msg, "GET / HTTP/1.0\r\nConnection: close\r\n\r\n", 80);
		break;
	case 8080:
		strncpy(msg, "GET / HTTP/1.0\r\n\r\n", 80);
		break;
	case 554:
		strncpy(msg, "GET / HTTP/1.0\r\n\r\n", 80);
		break;
	case 5555:
		strncpy(msg, "GET / HTTP/1.0\r\n\r\n", 80);
		break;
	default:
		strncpy(msg, "whololllo?\r\n\r\n", 80);
		break;
	}
}

void provideOutput(char *host, int port, char *msg) {
	char *serv;
	if (synOnly == TRUE) {
		return;
	} else if (port == 80 || port == 8080) {
		serv=matchBanner(msg);
		if (serv != NULL) {
			//TODOchar **serv_t = tokenize(serv);
			persistServ(host, port, serv);
serv = matchSpecial(msg);
                if (strcmp(serv, UNKNOWN) != 0) {
                        persistSpecialServ(host, port, serv);
                } 
		} else {
			persistServ(host, port, "UNKNOWN");
		}

	} else {
		serv = matchSpecial(msg);
		if (strcmp(serv, UNKNOWN) != 0) {
			persistSpecialServ(host, port, serv);
		} else {
			serv = match(msg);
			persistServ(host, port, serv);
		}
	}
	if (serv != NULL) {
		free(serv);
	}
}
