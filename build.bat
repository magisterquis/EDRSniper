@echo off

REM build.bat
REM Builds edrsniper
REM By J. Stuart McMurray
REM Created 20190518
REM Last Modified 20190518

copy c:\windows\system32\wpcap.dll .
copy c:\windows\system32\packet.dll .
gendef.exe wpcap.dll
gendef.exe packet.dll
dlltool.exe -d wpcap.def -D wpcap.dll -l libwpcap.a
dlltool.exe -d packet.def -D packet.dll -l libpacket.a
del wpcap.dll
del packet.dll
del wpcap.def
del packet.def
gcc -O2 -Wall -Inpcap-sdk-1.03\include -L. --pedantic -std=c11 -o edrsniper.exe edrsniper.c -lIphlpapi -lws2_32 -lwpcap -static
gcc -DSTEALTH -DIFCIDR="192.168.0.0/16" -DFILTER="tcp port 80 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" -O2 -Wall -Inpcap-sdk-1.03\include -L. --pedantic -std=c11 -o edrsniper.baked.exe edrsniper.c -lIphlpapi -lws2_32 -lwpcap -static
del libwpcap.a
del libpacket.a
dir edrsniper*.exe
