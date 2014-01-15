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


// This is a generic plugin template

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include "../../pers.c"

void onInitPlugin()
{
	openServiceFile();
}

void onStopPlugin()
{
	closeServFile();
}

void getServiceInput(int port, char *msg) {
   strncpy(msg, "GET / HTTP/1.0\r\n\r\n", 80);
}

void provideOutput(char *host, int port, char *msg)
{
	if (synOnly == FALSE) {
		//printf("I received [%s] from [%s:%d]\n", msg, host, port);
		persistServ(host, port, msg);
	}
}
