EDR Sniper
----------
Give it a BPF filter and it'll drop TCP connections when it sees packets from
the connection matching a BPF filter.  This is meant to kill EDR comms.

For legal use only.

Compilation
------------
This is painful.  My apologies.

First step is to install [Npcap](https://nmap.org/npcap/).  It might also work
with [WinPcap](https://www.winpcap.org/).  YMMV.  It's tested with installing
Npcap in WinPcap compatible mode and without loopback support.  The Npcap SDK
is also needed.  Grab it and extract it somewhere.

[TDM-GCC](http://tdm-gcc.tdragon.net/download) is the compiler assumed for the
rest of these instructions.  Microsoft's compiler will probably work as well
but it's not been tested.

Before actually compiling it's necessary to convert two libraries from Windows
DLLs to gcc/mingw-friendly archives (`.a` files).  Something like the following
should do the trick.

```batch
mkdir lib
copy c:\windows\system32\wpcap.dll .
copy c:\windows\system32\packet.dll .
gendef.exe wpcap.dll
gendef.exe packet.dll
dlltool.exe -d wpcap.def -D wpcap.dll -l lib\wptap.a
dlltool.exe -d packet.def -D packet.dll -l lib\packet.a
del wpcap.dll
del packet.dll
del wpcap.def
del packet.def
gcc -O2 -Wall -I npcap-sdk-1.02\include -L lib --pedantic -std=c11 -o edrsniper.exe z:\edrsniper.c -lIphlpapi -lws2_32 -lpcap -static
dir edrsniper.exe
```

Good luck.

Usage
-----
At the moment the only user-configurable parameter is the BPF filter used to
select which TCP streams to kill.  It's generally a good idea to filter on
SYN packets to cut down on error output.

```batch
edrsniper.exe "tcp port 80 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
```

It may be better to allow a specific IP through, i.e. a C2 server.

```batch
edrsniper.exe "tcp port 80 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and not host a.b.c.d"
```

If the above fail, plan B is to tunnel C2 comms over dns and kill all TCP.

```batch
edrsniper.exe tcp
```

Of course, all of the above need to be run elevated (e.g. with `runas`).

In the future, the BPF filter and ethernet device will be settable at compile
time and there will be a `STEALTH` macro which will disable output, hide the
window, and so on.

Capture Interface
-----------------
At the moment, the capture interface is the first one found which isn't a
loopabck interface and isn't an NdisWan Adapter.  In future versions this will
be configurable.

Error 317
---------
Unfortunately, the [return value](https://docs.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-settcpentry#return-value)
isn't reliable.  Specifically, `317` is returned both if `edrsniper` isn't
running with the right permission and if the TCP connection to be dropped
doesn't exist.  The end result is that there's now way to know what went wrong.

Windows :/

How It Works
------------
Under the hood, edrsniper watches for packets which match a filter and when it
finds one, extracts the source and destination IP/port pair which it then
passes to [`SetTcpEntry`](https://docs.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-settcpentry).
