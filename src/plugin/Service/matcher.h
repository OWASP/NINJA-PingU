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
#define httpInfoSize 16

#define camServSize 40
#define printServSize 8

#define telnetServSize 2
#define telnetInfoSize 1

#define sshServSize 1
#define sshInfoSize 3

#define ftpServSize 4
#define ftpInfoSize 6

#define smtpServSize 3
#define smtpInfoSize 5

#define osSize 7

regex_t cam_serv_matcher[camServSize];
const char *cam_serv_str[][2] = {   {"MOBOTIX", "IPCamera (MOBOTIX)"},
									{"Server: asic.NET", "ASIC Controller. Default admin:admin"},
									{"Server: gunicorn", "Camera. Default no pswd"},
									{"Server: TAC/Xenta", "router. Default root:root"},
									{"Server: NetEVI", "Camera. Default no pswd"},
									{"Server: EWS-NIC", "Priner"},
									{"Server: MWS/", "Camera. Default no pswd"},
									{"Server: NVR4CH", "Camera. Default admin:admin"},
									{"Server: go1984", "Camera. Default no pswd"},
									{"Server: Enigma2", "Smart TV. Default no pswd"},
									{"Server: IQinVision", "Camera"},
									{"Server: IPOffice", "Priner"},
									{"<title>Spectra", "IPCamera (Spectra)"},
									{"Server: Siemens Switzerland", "Central Communication Unit (Siemens)"},
									{"Network Camera", "IPCamera (AXIS CAM)"},	
									{"Control Center Launcher", "IPCamera (AXIS CAM)"},	
									{"EvoCam", "IPCamera (EvoCam)"},
									{"IP Camera", "IPCamera (IP Camera)"},
									{"Camera Web Server", "IPCamera (Camera Web Server)"},
									{"IPCam", "IPCamera (IP CAM)"},
									{"DhWebCookie", "IPCamera (IP Camera)"},
									{"VIDEO WEB SERVER", "VIDEO WEB SERVER)"},
									{"Camera Image", "IPCamera (Camera Image)"},
									{"Virata-EmWeb", "IPCamera (WebCam)"},
									{"WebCam", "IPCamera (WebCam)"},
									{"Blue Iris", "IPCamera (Blue Iris)"},
									{"BlueIris", "IPCamera (Blue Iris)"},
									{"Server: webcam", "IPCamera (WebCam Server)"},
									{"Server: GeoHttpServer", "IPCamera (GeoHttpServer)"},
									{"Techno Vision Security System", "IPCamera (Techno Vision Security System)"},
									{"Server: AquaController", "AquaController Device"},
									{"Server: TRMB", "GPS Station (TRMB)"},
									{"Server: LightTPD", "IPCamera (LightTPD)"},
									{"Server: Grandstream", "IPCamera (Grandstream)"},
									{"Server: ADH", "IPCamera (ADH-Web)"},
									{"Server: Mbedthis", "IPCamera (Mbedthis-AppWeb)"},
									{"Server: Muratec", "Manager Device"},
									{"Server: JAWS", "IPCamera (JAWS)"},
									{"Server: Indigo", "IPCamera (Indigo)"},
									{"Server: H264DVR", "IPCamera (H264DVR)"},
									{"Server: HyNetOS", "IPCamera (HyNetOS)"},
									{"axiscam", "IPCamera (axiscam)"}
							};

regex_t print_serv_matcher[printServSize];
const char *print_serv_str[][2] = { {"HP LaserJet", "Printer (HP LaserJet)"},
									{"HP Officejet", "Printer (HP Officejet)"},
									{"HP Photosmart", "Printer (HP Photosmart)"},
									{"<title>Photosmart", "Printer (Photosmart)"},
									{"Server: debut", "Printer (Brother)"},
									{"Server: CANON", "Printer (Canon)"},
									{"Server: KM-MFP-http", "Printer"},
									{"<title>HP Officejet", "Printer (HP Officejet)"}
							};

regex_t http_serv_matcher[httpServSize];
regex_t http_info_matcher[httpInfoSize];

const char *http_serv_str[][2] = { {"html", "http"},
							 {"HTTP", "http"}
							};

const char *http_info_str[][2] = {
							{"Server: ([^ ]*)", "()"},
							{"Basic realm=\"([^\"]*)", "()"},
							{"Mbedthis-AppWeb", "(Mbedthis-AppWeb)"},
							{"ZyXEL-RomPager", "(ZyXEL-RomPager)"},
							{"cisco-IOS", "(cisco-IOS)"},
							{"Router Webserver", "(Router Webserver)"},
							{"Allegro-Software-RomPager", "(Allegro-Software-RomPager)"},
							{"KEENETIC 4G", "(KEENETIC 4G)"},
							{"Hikvision-Webs", "(Hikvision-Webs)"},
							{"TP-LINK Wireless Router", "(TP-LINK Wireless Router)"},
							{"TP-LINK Wireless N Gigabit Router", "(TP-LINK Wireless N Gigabit Router)"},
							{"TP-LINK Wireless Lite N Router", "(TP-LINK Wireless Lite N Router)"},						
							{"Waveplus HTTPD", "(Waveplus HTTPD)"},
							{"Oracle XML DB/Oracle9i", "(Oracle XML DB/Oracle9i)"},
							{"Intoto Http Server", "(Intoto Http Server)"},
							{"Resin", "(Resin)"},
							};

regex_t telnet_serv_matcher[telnetServSize];
regex_t telnet_info_matcher[telnetInfoSize];

const char *telnet_serv_str[][2] = {{"User Access Verification", "Telnet"},
									{"Login", "Telnet"}
									};

const char *telnet_info_str[][2] = {{"microsoft", "microsoft"}
									};


regex_t ssh_serv_matcher[sshServSize];
regex_t ssh_info_matcher[sshInfoSize];

const char *ssh_serv_str[][2] = {{"SSH", "SSH"}
							};

const char *ssh_info_str[][2] = {  {"SSH-([0-9]*.[0-9]*-[a-zA-Z0-9./-]*)", "()"},
								{"OpenSSH", "(OpenSSH)"},
		 	 	 	 	 	 	 {"Cisco", "(Cisco)"}
							};

regex_t ftp_serv_matcher[ftpServSize];
regex_t ftp_info_matcher[ftpInfoSize];

const char *ftp_serv_str[][2] = {  {"ftp", "FTP"},
							 {"FileZilla Server", "FTP"},
							 {"530 Please login with USER and", "FTP"},
							 {"220 Inactivity timer", "FTP"}
							};
const char *ftp_info_str[][2] = {  {"FileZilla Server", "(FileZilla Server)"},
							 {"ProFTPD", "(ProFTPD)"},
							 {"Microsoft FTP Service", "(Microsoft FTP Server)"},	 
							 {"Welcome to Pure-FTPd", "(Pure-FTPd)"},
							 {"Palamax FTP service", "(Palamax)"},
							 {"vsFTPd", "(vsFTPd)"}
							};


regex_t smtp_serv_matcher[smtpServSize];
regex_t smtp_info_matcher[smtpInfoSize];

const char *smtp_serv_str[][2] = {   {"220*SMTP", "SMTP"},
									 {"554 SMTP", "SMTP"},
									 {"ESMTP", "SMTP"}
							};

const char *smtp_info_str[][2] = {  {"ESMTP Exim", "(Exim)"},
							 {"ESMTP Postfix", "(Postfix)"},
							 {"ESMTP Mail Carolo", "(Mail Carolo)"},
							 {"ESMTP MailEnable Service", "(MailEnable Service)"},	 
							 {"Microsoft ESMTP MAIL Service", "(Microsoft MAIL Service)"}
							};

regex_t osRegex[osSize];
const char *osRegexStr[][2] = {  {"ubuntu", " OS: Ubuntu"},
							{"debian", " OS: Debian"},
							{"Microsoft", " OS: Microsoft"},
							{"CentOS", " OS: CentOS"},
							{"suse", " OS: SUSE Linux"},
							{"Red Hat", " OS: Red Hat"},
							{"Linux", " OS: Linux"},
							{"Win32", " OS: Win32"}
							};

size_t maxGroups = 3;

regmatch_t groupArray[3];
