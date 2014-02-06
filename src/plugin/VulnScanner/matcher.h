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

#include "../../conf.h"


#define CPE_FILE "src/plugin/VulnScanner/official-cpe-dictionary_v2.3.xml"
#define NVD_FILE "src/plugin/VulnScanner/nvdcve-2.0-modified.xml"


//linked list to allocate cves
struct List {
	struct List *next;
	char *cve;
};

//Allocate CPE key value pairs
struct CPE_DATA {
	char *title;
	char *cpe;
	struct List *cve;
};

long long int nvdlen;
long long int cpelen;

//Allocate NVD key value pairs
struct NVD_DATA {
	char *cve;
	char *vulns;
};

// pointer of NVD pairs pointers
struct NVD_DATA **nvdPairs;

// pointer of CPE pairs pointers
struct CPE_DATA **cpePairs;
