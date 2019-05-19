EDR Sniper
----------
Give it a BPF filter and it'll drop TCP connections when it sees packets from
the connection matching a BPF filter.  This is meant to kill EDR comms.

At the moment only TCP over IPv4 is supported.

For legal use only.

Compilation
------------
This is painful.  My apologies.

### Install Npcap
First step is to install [Npcap](https://nmap.org/npcap/).  It might also work
with [WinPcap](https://www.winpcap.org/).  YMMV.  It's tested with installing
Npcap in WinPcap compatible mode and without loopback support.  The Npcap SDK
is also needed.  Grab it and extract it somewhere.

### Install the Compiler
[TDM-GCC](http://tdm-gcc.tdragon.net/download) is the compiler assumed for the
rest of these instructions.  Microsoft's compiler will probably work as well
but it's not been tested.

### Convert Libraries and Build
Before actually compiling it's necessary to convert two libraries from Windows
DLLs to gcc/mingw-friendly archives (`.a` files).  Something like the contents
of [`build.bat`](./build.bat) should do the trick.

Good luck.

### Compile-Time Options
The following macros can be set at compile time:

Macro                          | Description
-------------------------------|------------
`STEALTH`                     `| Redirect output to `NUL`.  In the future it will also hide the terminal window.
[`IFCIDR`](#capture-interface) | CIDR range to select capture interface
[`FILTER`](#filter)            | BPF filter to select TCP streams to drop

This is meant to make it easier to bake-in configuration for shoving the binary
into memory, running non-interactively, and so on.

Filter
------
Any TCP stream with a packet matching a BPF filter will be dropped.  The filter
can either be specified on the command-line at runtime or as a preprocessor
macro (i.e. `-DFILTER=<filter>`) at compile time.  It's generally a good idea
to filter on SYN packets to cut down on error output.

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

Capture Interface
-----------------
The interface on which to capture can be determined in two ways.  By default,
the first non-loopback, non-NdisWan adapter is used.  Alternatively, the
compile-time macro `IFCIDR` can be set to a CIDR range (e.g. `10.0.0.0/8`)
to select the first interface with an address in the given range.  A specific
address may be selected by using a netmask of `32`, e.g. `192.168.88.1/32`.

How It Works
------------
Under the hood, edrsniper watches for packets which match a filter and when it
finds one, extracts the source and destination IP/port pair which it then
passes to [`SetTcpEntry`](https://docs.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-settcpentry).

Error 317
---------
Unfortunately, the [value](https://docs.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-settcpentry#return-value)
returned by `SetTcpEntry` isn't reliable.  Specifically, `317` is returned both
if `edrsniper` isn't running with the right permission and if the TCP
connection to be dropped doesn't exist.  The end result is that there's no way
to know what went wrong.

Windows `:/`
