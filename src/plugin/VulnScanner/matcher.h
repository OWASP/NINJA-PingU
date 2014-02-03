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

#define httpServSize 2
#define httpInfoSize 2

regex_t http_serv_matcher[httpServSize];
regex_t http_info_matcher[httpInfoSize];

const char *http_serv_str[][2] = {
				{"html", "http"},
				{"HTTP", "http"}
				};

const char *http_info_str[][2] = {
				{"Server: ([^ ]*)", "()"},
				{"Basic realm=\"([^\"]*)", "()"},
				};


regex_t title_cpe_matcher;
regex_t str_cpe_matcher;

const char *title_cpe_regex = "<title xml:lang=\"en-US\">([^<]*)";
const char *str_cpe_regex = "<cpe-23:cpe23-item name=\"([^\"]*)";

regex_t nvd_entry_matcher;
regex_t nvd_cve_matcher;
regex_t nvd_cpe_matcher;

const char *nvd_entry_regex = "<entry([?|</entry>]))";
const char *nvd_cve_regex = "id=\"([^\"]*)";
const char *nvd_cpe_regex = "wqdwqdwqdwq";//vuln:vulnerable-software-list>([?|</vuln:vulnerable-software-list>)";

  

size_t maxGroups = 3;

regmatch_t groupArray[3];
regmatch_t groupArray2[3];

