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

#Lauches tuned terminator for better user experience
function run_terminator {
	oldVar=`echo $XDG_CONFIG_HOME`;
	echo $oldVar;
	export XDG_CONFIG_HOME="./lib";
	./lib/terminator/terminator --layout=npingu --maximise 2>/dev/null &
	export XDG_CONFIG_HOME=${oldVar};
}

#Tune Linux for better performance
function tune_linux {
	printf "Tune Linux for better performance(root required)[y/n]? ";
	read ans;
	if [ "$ans" == "y" ]; then
		su;
		ulimit -n 9119;
		su $LOGNAME;
	fi
}

echo "Compiling NINJA PingU";
compile_pingu;

#Checks successful compilation
if [ ! -f "bin/npingu" ]; then
	echo "Seems like the compilation was not successful :(";
else
	echo "NINJA PingU Compiled successfully";
	#todo fix this
	#tune_linux;
	echo "Invoking custom terminator, have fun.";
	run_terminator;
fi

