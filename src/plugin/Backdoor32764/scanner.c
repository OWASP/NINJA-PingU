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


#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include "../../pers.c"

//constants for the ou
char *vuln = "vulnerable";
char *patched = "patched";

//payload to look for 0x53634D4D and 0x4D4D6353
const char *payload = "ScMM";

void onInitPlugin()
{
	openServiceFile();
}

void onStopPlugin()
{
	closeServFile();
}

void getServiceInput(int port, char *msg) {
	strncpy(msg, "randomdata\r\n\r\n", 22);
}

void provideOutput(char *host, int port, char *msg)
{
	if(strstr(msg, payload) != NULL && synOnly == FALSE) {
		persistServ(host, port, vuln);
	} else {
		persistServ(host, port, patched);
	}
}
