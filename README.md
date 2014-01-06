"NINJA-PingU Is Not Just a Ping Utility" is a free open-source high performance network scanner and services discoverage tool for large scale  analyses.


Requeriments
============

 - Compiler
 - Linux box. Will not work niether on *BSD or Windows OS.
 - Hands and a Brain


Build
=====

$ make


Usage
=====

 #  sudo ./bin/npingu [OPTIONS] targets

 -t	Number of sender threads.
 -p	Port scan range. For instance, 80 or 20-80.
 -r	Ip address seed. For instance, 192.168.1.
 -d	Delay between packages sent (in usecs).
 -s	No service discoverage (less bandwith load, more hosts/time).
 -m	Module to run. For instance, Service.
 -h	Show this help.


Examples
========

   # ./bin/npingu -t 9 -p 20-80 -r 188.165.83.148-188.255.83.148 -d 1 -m Service

      -Targeted Hosts [188.165.83.148-188.255.83.148]
      -Targeted Port Range [20-80]
      -Threads [9]
      -Delay 1 usec
      -User the Service discoverage Module


   #  ./bin/npingu -t 5 -p 80 -s 74.125.0.0-74.125.255.255 #scan google

      -Targeted Hosts [74.125.0.0-74.125.255.255]
      -Targeted Port [80]
      -Threads [5]
      -s synOnly scan


Bugs & Contact
==============

Feel free to mail me with any problem, bug, suggestions or fixes at:
Guifre Ruiz <guifre.ruiz@owasp.org>


