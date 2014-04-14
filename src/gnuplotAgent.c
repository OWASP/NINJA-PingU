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

#include <stdio.h>

//TODO: this has to be refactored
#define plot_visualizer_cmd "su $SUDO_USER -c \"sensible-browser out/scan.png &>/dev/null\""


int run_cmd(const char *cmd)
{
	FILE *gnuplotOut = popen(cmd, "r");
	int status = pclose(gnuplotOut);
	if( status == -1 ) {
		printf("Could not run [%s]\n", cmd);
	}
	return status;
}


void make_plot(char *firstIp, unsigned int* ports[2])
{

	//get the last ip address scanned
	char *lastIp;
	lastIp = (char *) malloc(19 * sizeof(char));
	snprintf(lastIp, 19, "%d.%d.%d.%d", seed_ip[0], seed_ip[1], seed_ip[2], seed_ip[3]);

	int bufSize = 1000;
	char * newBuffer = (char *)malloc(bufSize);
	strncpy(newBuffer, "./lib/gnuplot -p -e 'set title \"Analysis Targets [", bufSize - (strlen(newBuffer) +1));
	strncat(newBuffer, firstIp, bufSize - (strlen(newBuffer) +1));
	strncat(newBuffer, "-", bufSize - (strlen(newBuffer) +1));
	strncat(newBuffer, lastIp, bufSize - (strlen(newBuffer) +1));
	strncat(newBuffer, "]\"; set logscale y; set terminal png; set output \"out/scan.png\";set xlabel \"Time (seconds)\";set ylabel \"Services\";set key left box;plot \"out/stats.out\" using 1 with linespoints title \"Scanned Services\", \"out/stats.out\" using 2 with linespoints title \"Alive Services in [", bufSize - (strlen(newBuffer) +1));
	if((*ports)[0] < (*ports)[1]) {
		sprintf(newBuffer + strlen(newBuffer), "%d", (*ports)[0]);
		strncat(newBuffer, " to ", bufSize - (strlen(newBuffer) +1));
		sprintf(newBuffer + strlen(newBuffer), "%d", (*ports)[1]);
	} else {
		sprintf(newBuffer+ strlen(newBuffer), "%d", (*ports)[0]);
	}
	strncat(newBuffer, "]\"' 2>/dev/null \0", bufSize - (strlen(newBuffer) +1));
	
	//run gnuplot
	int status = run_cmd(newBuffer);
	if (status != -1)
	{
		run_cmd(plot_visualizer_cmd);
	}
	//int stat = system(newBuffer);
	//printf("status is %d\n", stat);
	
		//	system("xdg-open out/scan.png");
	
}
