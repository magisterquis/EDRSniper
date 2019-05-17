/*
 * edrsniper.c
 * Windows program to drop TCP connections which match a BPF filter
 * By J. Stuart McMurray
 * Created 20190512
 * Last Modified 20190516
 */

#include <winsock2.h>
#include <winsock.h>
#include <windows.h>
#include <Iphlpapi.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* SNAPLEN is how much data to capture.  120 bytes should be plenty to extract
 * IPs and ports. */
#define SNAPLEN 120

/* ROWSTR_SIZE is the minimum size of the buffer used for pretty-printing TCP
 * table rows. */
#define ROWSTR_SIZE 46

void handler(u_char *usr, const struct pcap_pkthdr *hdr, const u_char *pkt);
void rowstr(PMIB_TCPROW row, char *buf);
void print_error(DWORD ret, PMIB_TCPROW row);

int
main(int argc, char **argv)
{
        char *dev, *filt;
        char errbuf[PCAP_ERRBUF_SIZE+1];
        int i, len;
        pcap_t *p;
        struct bpf_program prog;
        bpf_u_int32 net, mask;
        int l2hlen, dltype;
        pcap_if_t *dl, *d;

        memset(errbuf, 0, sizeof(errbuf));

        /* Set up pcap on the first non-loopback interface. */
        if (0 != pcap_findalldevs(&dl, errbuf)) {
                fprintf(stderr, "Unable to get capture devices: %s\n", errbuf);
                return 0;
        }
        for (d = dl; NULL != d; d = d->next) {
                if (PCAP_IF_LOOPBACK & d->flags || NULL != strstr(
                                        d->description, "NdisWan Adapter"))
                        continue;

                break;
        }
        if (NULL == d) {
                fprintf(stderr, "No non-loopback device found\n");
                return 13;
        }
        dev = d->name;
        if (NULL == (p = pcap_open_live(dev, SNAPLEN, 0, 10, errbuf))) {
                fprintf(stderr, "pcap_open_live: %s\n", errbuf);
                return 4;
        }
        printf("Will capture on %s (%s)\n", dev, d->description);

        /* Work out capture filter */
        len = 0;
        argc--;
        argv++;
        for (i = 0; i < argc; ++i)
                len += strlen(argv[i]) + 1;
        if (0 >= len || 0 == argc) {
                fprintf(stderr, "Usage: %s filter\n", argv[0]);
                return 2;
        }
        if (NULL == (filt = malloc(len))) {
                perror("malloc");
                return 3;
        }
        memset(filt, 0, len);
        for (i = 0; i < argc; ++i) {
                if (0 != i)
                        (void)strncat(filt, " ", len - 1 - strlen(filt));
                (void)strncat(filt, argv[i], len - 1 - strlen(filt));
        }
        if (0 != pcap_lookupnet(dev, &net, &mask, errbuf)) {
                fprintf(stderr, "pcap_loookupnet: %s\n", errbuf);
                return 6;
        }
        if (0 != pcap_compile(p, &prog, filt, 1, mask)) {
                fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(p));
                return 7;
        }
        if (0 != pcap_setfilter(p, &prog)) {
                fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(p));
                return 8;
        }
        pcap_freecode(&prog);
        printf("Capture filter: %s\n", filt);
        free(filt); filt = NULL;

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
        printf("Datalink type: %s (%s)\n",
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
                fprintf(stderr, "Packet not IPv4.  Considering adding \"and "
                                "ip\" to the filter.\n");
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
                        fprintf(stderr, "Error 317 dropping %s", buf);
                        return;
                default:
                        /* Do YOU want to figure out https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-formatmessage ? */
                        printf("Unable to kill %s: error number %lu\n", buf,
                                        ret);
                        return;
        }
}
