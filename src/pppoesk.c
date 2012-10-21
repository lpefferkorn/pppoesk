/*
* Copyright (C) 2006,2012 Loic Pefferkorn <loic-pppoesk@loicp.eu>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; version 2 of the License.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>     // memset
#include <pcap.h>
#include <libnet.h>
#include "config.h"
#include "pppoe.h"

void usage(void);
void error(char *errmsg, ...);
void extract_pppoe_data(u_char *packet, unsigned short *session_id, unsigned char src_mac[6], unsigned char dst_mac[6]);
void forge_packet(char *interface, unsigned short session_id, unsigned char src_mac[6], unsigned char dst_mac[6]);

#define PAYLOAD_SIZE    50

/* Tested platforms :
- GNU/Linux x86 (Ubuntu Dapper,Edgy)
- FreeBSD x86 (6.0-RELEASE 6.2-BETA3)
*/

/* TODO :
- add interactive mode where you can specify both source MAC and session ID
- test link layer with pcap_datalink
- print pppoe->code
- typedef src/dst mac
- check if session_id is successfully extracted
- segfault if lo interface
- use libnet structs instead of OS ones
- work with both {little,big} endian archs
*/

#ifndef ETH_ALEN
#define ETH_ALEN    6
#endif

void usage()
{
        printf("Usage:\n"
                "  -i ethernet interface used to send packet\n"
                "  -p only print session info (MACs, sessionID) then exit\n"
                "  -s source MAC address to use in the forged packet\n"
                "  -h print this help\n"
		"  -v print version\n"
        );
        exit(1);
}

void error(char *errmsg, ...)
{
        va_list list;
        va_start(list, errmsg);

        vfprintf(stderr, errmsg, list);
        va_end(list);
        exit(1);
}

void extract_pppoe_data(u_char *packet, unsigned short *session_id, unsigned char src_mac[6], unsigned char dst_mac[6])
{
    /* pppoe packet
     *
     * ethernet 14 bytes
     *                      6 bytes         :       destination MAC
     *                      6 bytes         :       source MAC
     *                      2 bytes         :       type (0x8863 PPPoE discovery - 0X8864 PPPoE session)
     * 
     * pppoed       min 6 bytes
     *                      1 byte          :       type (1)
     *                      1 byte          :       version (1)
     *                      1 byte          :       code (0x09 PADI - 0x07 PADO - 0x19 PADR - 0xa7 PADT )           
     *                      2 bytes         :       session ID
     *                      min 1 byte      :       payload length
     *                       
     */

    struct libnet_ethernet_hdr *eptr;
    struct pppoe_hdr *pppoe;

    eptr = (struct libnet_ethernet_hdr *) packet;
    pppoe = (struct pppoe_hdr *) (packet + sizeof(struct libnet_ethernet_hdr));

    int pos = 0;
    for (pos =0;pos<=5;pos++)
    {
        src_mac[pos] = eptr->ether_shost[pos];
        dst_mac[pos] = eptr->ether_dhost[pos];
    }

    *session_id = pppoe->sid;
}

void forge_packet(char *interface, unsigned short session_id, unsigned char src_mac[6], unsigned char dst_mac[6])
{
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l;
    libnet_ptag_t *t;

    u_int8_t payload[PAYLOAD_SIZE];
    u_int32_t payload_s;
    u_int8_t *ptr;
    u_int16_t ether_type = 0x8863;


    payload_s = PAYLOAD_SIZE;
    memset(payload, 0, sizeof(payload));    

    ptr = payload;

    *ptr = 0x11;            // PPPoE type 1 version 1
    *(++ptr) = 0xa7;        // PADT packet

    /* split session_id short into 2 char */
    char tmp1 = session_id & 0x00FF;
    char tmp2 = session_id >> 8;

    *(++ptr) = tmp1;
    *(++ptr) = tmp2;

    l = libnet_init(LIBNET_LINK_ADV, interface, errbuf);
    if (l == NULL)
        error("libnet_init() failed: %s", errbuf);


    t = libnet_build_ethernet(dst_mac,                  /* destination */
                                src_mac,                /* source */
                                ether_type,             /* PPPoE discovery */
                                payload,                /* payload */
                                payload_s,              /* size of payload */
                                l,                      /* handle */
                                0);                     /* build new header */

    if(t == NULL)
        error("libnet_build_ethernet() failed: %s\n", libnet_geterror(l));

    // compute checksums
    if (libnet_adv_cull_packet(l,  (u_int8_t **) &payload, &payload_s) == -1)
        error("libnet_adv_cull_packet() failed: %s\n", libnet_geterror(l));

    int c = libnet_write(l);

    if (c == -1)
    {
        error("libnet_write() failed: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(1);
    }

    libnet_destroy(l);
}

int main(int argc, char **argv)
{

    char *interface = NULL;                     /* ethernet interface used to sniff and send packet  */
    int print_only_flag = 0;
    int fake_src_mac_flag = 0;
    int ch;
    unsigned int fake_mac[6];                         /* source MAC address */

    while ((ch = getopt(argc, argv, "i:ps:hv")) != -1)
    {
        switch (ch)
        {
            case 'p':
		printf("**Print only mode, no packet will be sent !**\n");
                print_only_flag = 1;
                break;
            case 'i':
                interface = optarg;
                break;
            case 's':
                fake_src_mac_flag = 1;
                if (sscanf(optarg, "%x:%x:%x:%x:%x:%x",
                            &fake_mac[0],
                            &fake_mac[1],
                            &fake_mac[2],
                            &fake_mac[3],
                            &fake_mac[4],
                            &fake_mac[5]) != ETH_ALEN)
                    error("err: illegal MAC addr\n");
                else
                    printf("Faking src MAC addr...\n");
                break;
	    case 'v':
		printf("%s\n", PACKAGE_STRING);	/* provided by AC_INIT() in config.h */
		exit(0);
            case 'h':
            case '?':
            default:
                usage();
        }
    }

    if (interface == NULL)
        error("err: No ethernet interface specified !\n",
              "You must specify one using -i parameter \n");
    else
        printf("Using ethernet interface : %s\n", interface);

    /* libpcap stuff */

    char errbuf[PCAP_ERRBUF_SIZE];              /* buffer for libpcap error message */
    pcap_t *handle;                             /* session handle */
    char filter[] = "pppoes or pppoed";       	/* filter */
    struct bpf_program compiled_filter;         /* compiled filter */
    bpf_u_int32 ip = 0;                         /* interface  ip */
    struct pcap_pkthdr header;                  /* header that pcap gives us */
    u_char *packet;                             /* captured packet */

    if (getuid() != 0)
        error("err: you must be root !\n");

    if ((handle = pcap_open_live(interface, 1000, 1, 1000, errbuf)) == NULL)	/* using 1000 as timeout, like tcpdump does */
        error("pcap_open_live() failed: %s  %s\n", interface, errbuf);

    if (pcap_compile(handle, &compiled_filter, filter, 0, ip) == -1 )
        error("pcap_compile() failed: %s\nUsing libpcap0.7 library ? Please install libpcap >= 0.8 \n", pcap_geterr(handle));

    if (pcap_setfilter(handle, &compiled_filter) == -1)
        error("pcap_setfilter() failed: %s\n", pcap_geterr(handle));

    /* now we wait for a packet matching our filter*/
    printf("Waiting for packet...\n");

    /* multiple packets
    pcap_loop(handle, -1, analyse_packet, NULL);
    */

    /* capture one packet */
    if ((packet = pcap_next(handle, &header)) == NULL)
        error("pcap_next() failed: %s\n", pcap_geterr(handle));

    u_short session_id = 0x0;               /* PPPoE session ID */
    u_char  src_mac[6],                     /* Access concentrator's ethernet MAC address */
            dst_mac[6];                     /* Ethernet interface's MAC address 
                                              (where our DSL modem is connected to) */

    extract_pppoe_data(packet, &session_id, src_mac, dst_mac);

    printf("PPPoE session ID: %x\n", (unsigned int) session_id);

    int pos;

    /* if we want to spoof src MAC addr replace the real addr */
    if (fake_src_mac_flag == 1)
    {
        unsigned int *p = fake_mac;
        for(pos=0;pos<ETH_ALEN;pos++)
            src_mac[pos] = *p++; 
    }

    u_char *bit = src_mac;

    printf("Ethernet interface MAC: ");
    for(pos=0;pos<ETH_ALEN;pos++)
    {
        printf("%.2x", (unsigned char) *bit++);
        if (pos != ETH_ALEN-1)
            printf(":");
    }
    printf("\n");

    printf("Access Concentrator MAC: ");
    bit = dst_mac;

    for(pos=0;pos<ETH_ALEN;pos++)
    {
        printf("%.2x", (unsigned char) *bit++);
        if (pos != ETH_ALEN-1)
            printf(":");
    }
    printf("\n");

    pcap_close(handle);

    if (print_only_flag == 1)
        exit(0);

    forge_packet(interface, session_id, src_mac, dst_mac);

    printf("Packet sent !\n");

    return 0;

}
