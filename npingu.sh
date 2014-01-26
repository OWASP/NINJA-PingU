#!/bin/bash
#
#   OWASP NINJA PingU: Is Not Just a Ping Utility
#
#   Copyright (C) 2014 Guifre Ruiz <guifre.ruiz@owasp.org>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#/

#Compiles NINJA PingU
function compile_pingu {
	make npingu > /dev/null;
}

function run_npingu {
	tmux new-session -d 'echo -e "\e[34mHosts Found\n";tail -F out/hostsScanned.out' \; split-window -d -p 30 \; attach \; split-window -h -p 90 'echo -e "\e[32m\e[107mServices Found\n"; tail -F out/servicesScanned.out' \; split-window -h 'tail -F out/debug.out' \; select-pane -t 3 \; split-window -h -p 30 'echo -e "\e[91mEmbedded Devices Found\n";tail -F out/specialServicesScanned.out' \;  select-pane -t 3 \; attach \; send-keys -t "3" C-z './bin/npingu' Enter;
}

function show_header {
	printf "\nOWASP NINJA PingU Is Not Just A Ping Utility\n=============================================\n\n";
}

avoid_drop_pkt="iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST,RST RST,RST -j DROP;";
inc_descriptors="ulimit -n 99999";
undo_avoid_drop_pkt="iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST,RST RST,RST -j DROP";


show_header;
echo "-Compiling NINJA PingU";
compile_pingu;

#Checks successful compilation
if [ ! -f "bin/npingu" ]; then
	echo "-Seems like the compilation was not successful :(";
else
	echo "-NINJA PingU Compiled successfully";
	printf "¿Tune Linux for better performance(root required)[y/n]? ";
	read ans;
	if [ "$ans" == "y" ]; then
		export -f run_npinguu
		su -c "${inc_descriptors} ${avoid_drop_pkt} run_npinguu";
	else
		echo "running $run_npingu";
		run_npinguu;
	fi
fi

