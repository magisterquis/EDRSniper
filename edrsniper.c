/*
 * edrsniper.c
 * Windows program to drop TCP connections which match a BPF filter
 * By J. Stuart McMurray
 * Created 20190512
 * Last Modified 20190519
 */

#include <sys/stat.h>

#include <winsock2.h>
#include <winsock.h>
#include <windows.h>
#include <Iphlpapi.h>
#include <Share.h>

#include <fcntl.h>
#include <io.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Because Windows... */
#define STRINGIZE(x) #x
#define STRINGIZE_VALUE_OF(x) STRINGIZE(x)
/* Above from https://stackoverflow.com/questions/2410976/how-to-define-a-string-literal-in-gcc-command-line/7955490 */

/* SNAPLEN is how much data to capture.  120 bytes should be plenty to extract
 * IPs and ports. */
#define SNAPLEN 120

/* ROWSTR_SIZE is the minimum size of the buffer used for pretty-printing TCP
 * table rows. */
#define ROWSTR_SIZE 46

void handler(u_char *usr, const struct pcap_pkthdr *hdr, const u_char *pkt);
void rowstr(PMIB_TCPROW row, char *buf);
void print_error(DWORD ret, PMIB_TCPROW row);
int  has_address_in_cidr(const struct pcap_addr *pa, uint32_t mask, uint32_t net);
void parse_cidr(const char *s, uint32_t *mask, uint32_t *net);

int
main(int argc, char **argv)
{
        char *dev, *filt;
        char errbuf[PCAP_ERRBUF_SIZE+1];
        pcap_t *p;
        struct bpf_program prog;
        bpf_u_int32 net, mask;
        int l2hlen, dltype;
        pcap_if_t *dl, *d;
#ifdef STEALTH
        int fd, fdi;
#endif /* #ifdef STEALTH */
#ifndef FILTER
        int len, ai;
#endif
        /* mask and net hold a CIDR range if we're choosing our adapter by
         * CIDR. */
#ifdef IFCIDR
        uint32_t cmask;
        uint32_t cnet;
#endif /* #ifdef IFCIDR */


        /* Stealth mode.  Write to NULL and close the window */
#ifdef STEALTH
        /* Close the console window */
        ShowWindow(GetConsoleWindow(), SW_HIDE);

        /* Close stdin/out/err and remap fds < 3 to NUL */
        for (fd = 0; fd < 3; ++fd) {
                if (0 != _close(fd)) {
                        perror("_close");
                        return 12;
                }
        }
        if (0 != _sopen_s(&fd, "NUL", _O_WRONLY, _SH_DENYNO,
                                _S_IREAD | _S_IWRITE)) {
                perror("_sopen_s");
                return 14;
        }
        for (fdi = 0; fdi < 3; ++fdi) {
                if (0 != _dup2(fd, fdi)) {
                        perror("_dup2");
                        return 15;
                }
        }
#endif /* #ifdef STEALTH */

        /* Work out the CIDR range for the interface, if we've got one */
#ifdef IFCIDR
        parse_cidr(STRINGIZE_VALUE_OF(IFCIDR), &cmask, &cnet);
#endif /* #ifdef IFCIDR */

        memset(errbuf, 0, sizeof(errbuf));

        /* Set up pcap on the first suitable interface. */
        if (0 != pcap_findalldevs(&dl, errbuf)) {
                fprintf(stderr, "Unable to get capture devices: %s\n", errbuf);
                return 0;
        }
        for (d = dl; NULL != d; d = d->next) {
#ifdef IFCIDR
                if (!has_address_in_cidr(d->addresses, cmask, cnet))
#else /* #ifdef IFCIDR */
                if (PCAP_IF_LOOPBACK & d->flags || NULL != strstr(
                                        d->description, "NdisWan Adapter"))
#endif
                        continue;

                break;
        }
        if (NULL == d) {
                fprintf(stderr, "No suitable device found\n");
                return 13;
        }
        dev = d->name;
        if (NULL == (p = pcap_open_live(dev, SNAPLEN, 0, 10, errbuf))) {
                fprintf(stderr, "pcap_open_live: %s\n", errbuf);
                return 4;
        }
        printf("Capture device: %s (%s)\n", dev, d->description);

        /* Work out capture filter */
#ifdef FILTER
        filt = STRINGIZE_VALUE_OF(FILTER);
#else /* #ifdef FILTER */
        len = 0;
        argc--;
        argv++;
        for (ai = 0; ai < argc; ++ai)
                len += strlen(argv[ai]) + 1;
        if (0 >= len || 0 == argc) {
                fprintf(stderr, "Please supply a BPF filter\n");
                return 2;
        }
        if (NULL == (filt = malloc(len))) {
                perror("malloc");
                return 3;
        }
        memset(filt, 0, len);
        for (ai = 0; ai < argc; ++ai) {
                if (0 != ai)
                        (void)strncat(filt, " ", len - 1 - strlen(filt));
                (void)strncat(filt, argv[ai], len - 1 - strlen(filt));
        }
#endif /* #ifdef FILTER */
        if (0 != pcap_lookupnet(dev, &net, &mask, errbuf)) {
                fprintf(stderr, "pcap_loookupnet: %s\n", errbuf);
                return 6;
        }
        if (0 != pcap_compile(p, &prog, filt, 1, mask)) {
                fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(p));
                fprintf(stderr, "Filter: %s\n", filt);
                return 7;
        }
        if (0 != pcap_setfilter(p, &prog)) {
                fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(p));
                return 8;
        }
        pcap_freecode(&prog);
        printf("Capture filter: %s\n", filt);
#ifndef FILTER
        free(filt); filt = NULL;
#endif /* #ifndef FILTER */

        /* Work out how big the layer-2 header is */
        switch (dltype = pcap_datalink(p)) {
                case DLT_EN10MB:
                        l2hlen = 14; /* Doesn't handle 802.1Q */
                        break;
                case DLT_RAW:
                case DLT_LOOP:
                        l2hlen = 0;
                        break;
                default:
                        fprintf(stderr, "unsupported datalink type %s (%s)",
                                        pcap_datalink_val_to_name(dltype),
                                        pcap_datalink_val_to_description(dltype));
                        return 9;
        }
        printf("Datalink type:  %s (%s)\n",
                        pcap_datalink_val_to_name(dltype),
                        pcap_datalink_val_to_description(dltype));

        /* Print packet contents */
        if (0 != pcap_loop(p, -1, handler, (u_char *)&l2hlen)) {
                fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(p));
                return 10;
        }

        return 0;
}

/* handler is the callback passed to pcap_loop */
void
handler(u_char *usr, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
        int l2hlen, iphlen;
        MIB_TCPROW frow, rrow;
        int cap, fret, rret;
        char rsbuf[ROWSTR_SIZE];

        l2hlen = *(int *)usr;
        cap = (int)hdr->caplen;

        /* Skip Layer 2 header */
        if (cap < l2hlen) {
                fprintf(stderr, "Packet size %i too small for %i byte "
                                "L2 header\n", hdr->caplen, l2hlen);
                return;
        }
        cap -= l2hlen;
        pkt += l2hlen;

        /* Make sure we're at an IPv4 header */
        if (0x40 != (*pkt & 0xF0)) {
                fprintf(stderr, "Non-IPv4 packet found.  Considering adding "
                                "\"and ip\" to the filter.\n");
                return;
        }
        /* Make sure we've got TCP next */
        if (0x06 != *(pkt + 9)) {
                fprintf(stderr, "Non-TCP packet (protocol %u) found.  "
                                "Consider adding \"and tcp\" to the filter.\n",
                                *(pkt + 9));
                return;
        }
        /* IP header length */
        iphlen = 4 * (*pkt & 0x0F);
        /* Get IP addresses */
        if (iphlen > cap) {
                fprintf(stderr, "Packet size %i truncates IP header\n",
                                hdr->caplen);
                return;
        }
        frow.dwLocalAddr = rrow.dwRemoteAddr = *((DWORD *)(pkt + 12));
        rrow.dwLocalAddr = frow.dwRemoteAddr = *((DWORD *)(pkt + 16));
        cap -= iphlen;
        pkt += iphlen;

        /* Get ports */
        if (4 > cap) {
                fprintf(stderr, "Packet size %i too small to extract "
                                "TCP ports", hdr->caplen);
                return;
        }
        frow.dwLocalPort = rrow.dwRemotePort = (DWORD)(*(uint16_t *)pkt);
        rrow.dwLocalPort = frow.dwRemotePort = (DWORD)(*(uint16_t *)(pkt+2));
        
        /* Set the "forget the connection" flag */
        frow.dwState = rrow.dwState = MIB_TCP_STATE_DELETE_TCB;

        /* Ask Windows to forget the connection */
        fret = rret = 0;
        memset(rsbuf, 0, sizeof(rsbuf));
        if (NO_ERROR == (fret = SetTcpEntry(&frow))) {
                rowstr(&frow, rsbuf);
        } else if (NO_ERROR == (rret = SetTcpEntry(&rrow))) {
                rowstr(&frow, rsbuf);
        }
        if (0 != *rsbuf) { /* One worked */
                printf("Dropped %s\n", rsbuf);
                return;
        }

        print_error(fret, &frow);
        print_error(rret, &rrow);
}

/* rowstr puts a pretty-printed version of row into buf, which will be NULL-
 * terminated on return. */
void
rowstr(PMIB_TCPROW row, char *buf) {
        struct in_addr ia;
        memset(buf, 0, ROWSTR_SIZE);

        ia.s_addr = row->dwLocalAddr;
        (void) strncat(buf, inet_ntoa(ia),
                        ROWSTR_SIZE - 1 - strlen(buf));
        (void) strncat(buf, ":", ROWSTR_SIZE - 1 - strlen(buf));
        (void) snprintf(buf + strlen(buf), ROWSTR_SIZE - 1 - strlen(buf), "%hu",
                        ntohs((u_short)row->dwLocalPort));
        (void) strncat(buf, "<->", ROWSTR_SIZE - 1 - strlen(buf));
        ia.s_addr = row->dwRemoteAddr;
        (void) strncat(buf, inet_ntoa(ia),
                        ROWSTR_SIZE - 1 - strlen(buf));
        (void) strncat(buf, ":", ROWSTR_SIZE - 1 - strlen(buf));
        (void) snprintf(buf + strlen(buf), ROWSTR_SIZE - 1 - strlen(buf), "%hu",
                        ntohs((u_short)row->dwRemotePort));
}

/* print_error prints an error message based on the return value ret and the
 * row row. */
void
print_error(DWORD ret, PMIB_TCPROW row)
{
        char buf[ROWSTR_SIZE];
        rowstr(row, buf);
        switch (ret) {
                case ERROR_ACCESS_DENIED:
                        fprintf(stderr, "Access denied dropping %s\n", buf);
                        return;
                case ERROR_INVALID_PARAMETER:
                        fprintf(stderr, "Invalid parameter in %s\n", buf);
                        return;
                case ERROR_NOT_SUPPORTED:
                        fprintf(stderr, "IPv4 transport not configured.  "
                                        "Unpossible.\n");
                        exit(11);
                case 317:
#ifndef NO317
                        fprintf(stderr, "Error 317 dropping %s\n", buf);
#endif /* #ifndef NO317 */
                        return;
                default:
                        /* Do YOU want to figure out https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-formatmessage ? */
                        printf("Unable to kill %s: error number %lu\n", buf,
                                        ret);
                        return;
        }
}

/* has_address_in_cidr returns nonzero if any of the addressess in the linked
 * list pa are in the CIDR range described by mask and net.  Only AF_INET
 * addresses will be considered. */
int
has_address_in_cidr(const struct pcap_addr *pa, uint32_t mask, uint32_t net)
{
        struct sockaddr_in *sin;
        /* Walk the list until we find a matching address or run out of
         * addresses. */
        for (; NULL != pa; pa = pa->next) {
                /* Make sure we've got an IPv4 address */
                if (AF_INET != pa->addr->sa_family)
                        continue;
                sin = (struct sockaddr_in *)(pa->addr);
                /* If the address matches, we're good. */
                if (net == (mask & sin->sin_addr.s_addr))
                        return 1;
        }

        /* If we made it here, none of the addresses match. */
        return 0;
}

#ifdef IFCIDR
/* parse_cidr parses the cidr range s which should be in address/bits notation
 * and places the masked network portion in net and the mask in mask.  The
 * program is terminated if s doesn't contain a valid CIDR range. */
void
parse_cidr(const char *s, uint32_t *mask, uint32_t *net)
{
        char a[21]; /* Should be long enough */
        char *ms, *end;
        unsigned long b;

        /* Copy s if it's short enough */
        memset(a, 0, sizeof(a));
        if (sizeof(a) - 1 < strlen(s)) {
                fprintf(stderr, "Interface cidr too long\n");
                exit(18);
        }
        strncpy(a, s, sizeof(a)-1);

        /* Find the start of the mask */
        if (NULL == (ms = strstr(a, "/"))) {
                fprintf(stderr, "CIDR range missing a /\n");
                exit(16);
        }
        *ms = '\0';
        ms++;

        /* Get the IPv4 address */
        if (INADDR_NONE == (*net = inet_addr(a))) {
                fprintf(stderr, "Invalid IPv4 address %s\n", s);
                exit(17);
        }

        /* Work out the netmask */
        b = strtoul(ms, &end, 0);
        if ('\0' == ms[0] || '\0' != *end) {
                fprintf(stderr, "Invalid mask %s\n", ms);
                exit(19);
        }
        if (32 < b) {
                fprintf(stderr, "Netmask of %lu bits too large\n", b);
                exit(20);
        }
        *mask = htonl(0xFFFFFFFF - ((1 << (32-b)) - 1));

        /* Turn the address into just the network number */
        *net &= *mask;
}
#endif /* #ifdef IFCIDR */
