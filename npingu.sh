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
	./lib/tmux new-session -d 'echo -e "\e[34mHosts Found\n";tail -F out/hostsScanned.out' \; split-window -d -p 30 \; attach \; split-window -h -p 85 'echo -e "\e[32m\e[107mServices Found\n"; tail -F out/servicesScanned.out' \; split-window -h 'tail -F out/debug.out' \; select-pane -t 3 \; split-window -h -p 45 'echo -e "\e[91mEmbedded Devices Found\n";tail -F out/specialServicesScanned.out' \;  select-pane -t 3 \; attach \; setw -g mode-mouse on \; set -g mouse-select-pane on  \; send-keys -t "3" C-z './bin/npingu' Enter;
}

avoid_drop_pkt="iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST,RST RST,RST -j DROP";
inc_descriptors="ulimit -n 99999";
undo_avoid_drop_pkt="iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST,RST RST,RST -j DROP";
exit_alias="alias exit='tmux kill-window -t :0'";

show_header;
echo "-Compiling NINJA PingU";
compile_pingu;

#Checks successful compilation
if [ ! -f "bin/npingu" ]; then
	echo "-Seems like the compilation was not successful :(";
else
	echo "-NINJA PingU Compiled successfully";
	printf "¿Tune Linux for better performance(root required)[y/n]? ";
	read tune;
	printf "¿Launch npingu UI[y/n]? ";
	read ui;
	if [ "$tune" == "y" ]  &&  [ "$ui" == "y" ]; then
		export -f run_npingu
		su -c "${exit_alias}; ${inc_descriptors}; ${avoid_drop_pkt}; run_npingu";
	elif  [ "$tune" == "n" ]  &&  [ "$ui" == "y" ]; then
		export -f run_npingu
		su -c "$exit_alias}; run_npingu";
	elif  [ "$tune" == "y" ]  &&  [ "$ui" == "n" ]; then
		su -c "${inc_descriptors}; ${avoid_drop_pkt}; ./bin/npingu -h";
	elif [ "$tune" == "n" ]  &&  [ "$ui" == "n" ]; then
		./bin/npingu -h;
	fi
fi


