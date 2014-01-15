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

#include <dlfcn.h>

#include "stats.c"


void (*onInitPlugin)();
void (*onStopPlugin)();
void (*provideOutput)(char *host, int port, char *msg);
char (*getServiceInput)(int port, char *msg);

void loadMethods() {
	char *error;
	char plugPath[50];
	strcpy(plugPath, "./src/plugin/");
	strncat(plugPath, module, 22);
	strcat(plugPath, "/scanner.so");
	if( access( plugPath, F_OK ) == -1  ) {
	    printf("\nERROR!!!\n\tPlugin %s does not exists\n", plugPath);
	    exit(-1);
	}

	void* libhandle = dlopen(plugPath, RTLD_NOW);
	if (!libhandle) {
		printf("Error loading DSO: %s\n", dlerror());
		return;
	}
	
	*(void **) (&getServiceInput) = dlsym(libhandle, "getServiceInput");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "%s\n", error);
		exit (EXIT_FAILURE);
	}
	
	*(void **) (&provideOutput) = dlsym(libhandle, "provideOutput");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "%s\n", error);
		exit (EXIT_FAILURE);
	}
	
	*(void **) (&onInitPlugin) = dlsym(libhandle, "onInitPlugin");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "%s\n", error);
		exit (EXIT_FAILURE);
	}

	*(void **) (&onStopPlugin) = dlsym(libhandle, "onStopPlugin");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "%s\n", error);
		exit (EXIT_FAILURE);
	}


}
