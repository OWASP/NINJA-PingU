NINJA PingU
===========
NINJA-PingU Is Not Just a Ping Utility is a free open-source high performance network scanner tool for large scale analyses. It has been designed with performance as its primary goal and developed as a framework to allow easy plugin creation.

It comes out of the box with a set of plugins for services analysis and embedded devices discoverage. More information about those can be found in its home page at http://owasp.github.io/NINJA-PingU


Requirements
------------
      - gcc
      - Linux box. Will not work neither on *BSD or Windows OS.
      - Root Privileges


Setting Up NINJA PingU
---------------------
       $ git clone https://github.com/OWASP/NINJA-PingU.git; cd ninjaPingu; ./npingu.sh

Usage
-----
 #  sudo ./bin/npingu [OPTIONS] targets

 -t	Number of sender threads.
 -p	Port scan range. For instance, 80 or 20-80.
 -d	Delay between packages sent (in usecs).
 -s	No service discoverage (less bandwith load, more hosts/time).
 -m	Module to run. For instance, Service.
 -h	Show this help.
 [targets] Ip address seed. For instance, 192.168.1. or 1.1.1.1-255.0.0.0


 NINJA Pingu comes with a bash script to automate process compilation, operating system performance tuning, and enhanced user interface with terminator integration. It can be run by running the following command.
 	
 	$ ./npingu.sh


Examples
--------
   # ./bin/npingu -t 3 -p 20-80 188.1.1.1-188.255.1.1 -d 1 -m Service

      -Targeted Hosts [188.165.83.148-188.255.83.148]
      -Targeted Port Range [20-80]
      -Threads [3]
      -Delay 1 usec
      -Use the Service discoverage Module


   #  ./bin/npingu -t 5 -p 80 -s 74.125.0.0-74.125.255.255 #scan google

      -Targeted Hosts [74.125.0.0-74.125.255.255]
      -Targeted Port [80]
      -Threads [5]
      -s synOnly scan

Bugs & Contact
--------------
Feel free to mail me with any problem, bug, suggestions or fixes at:
Guifre Ruiz <guifre.ruiz@owasp.org>

Visit http://owasp.github.io/NINJA-PingU for more information about NINJA PingU.

License
-------
Code licensed under the GPL v3.0.
