#include <stdio.h>
#include <unistd.h>

#include "msg.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netapi.h"
#include "net/gnrc/netif/hdr.h"

#define DATA                    "abc"

#define L2ADDR_LEN              (8U)
#define DST_L2ADDR_SHORT        "C3:DA"
#define DST_L2ADDR_LONG         "00:12:4b:00:06:15:a5:45"

#define SRC_PAN                 (0x0023)

#define AUTOACK                 NETOPT_ENABLE
#define ACK_REQ                 NETOPT_DISABLE

int main(void)
{
    kernel_pid_t ifs[GNRC_NETIF_NUMOF], dev;
    gnrc_pktsnip_t *pkt, *hdr;
    gnrc_netif_hdr_t *nethdr;

    size_t data_len;
    uint8_t flags = 0x00;
    uint8_t dst_l2addr[8];

    if (gnrc_netif_get(ifs) == 0) {
        puts("No interfaces found! Exiting.\n");
        return 1;
    }

    /* get interface */
    dev = ifs[0]; 

    /* configure interface */
    uint8_t l2addr_len = L2ADDR_LEN;
    gnrc_netapi_set(dev, NETOPT_SRC_LEN, 0, &l2addr_len, 2);

    uint8_t autoack = AUTOACK;
    gnrc_netapi_set(dev, NETOPT_AUTOACK, 0, &autoack, 1);

    uint8_t ack_req = ACK_REQ;
    gnrc_netapi_set(dev, NETOPT_ACK_REQ, 0, &ack_req, 1);

    uint16_t src_pan = SRC_PAN;
    gnrc_netapi_set(dev, NETOPT_NID, 0, &src_pan, 2);

    if (l2addr_len == 0) {
        flags |= GNRC_NETIF_HDR_FLAGS_BROADCAST;
    }

    /* get destination address */
    gnrc_netif_addr_from_str(dst_l2addr, sizeof(dst_l2addr), 
                           l2addr_len < 8 ? DST_L2ADDR_SHORT : DST_L2ADDR_LONG);

    char *data = DATA;
    data_len = strlen(data);
    if (data_len == 0) {
        pkt = NULL;
    }
    else {
        pkt = gnrc_pktbuf_add(NULL, data, data_len, GNRC_NETTYPE_UNDEF);
        if (pkt == NULL) {
            puts("error: packet buffer full");
            return 1;
        }
    }
    hdr = gnrc_netif_hdr_build(NULL, 0, dst_l2addr, l2addr_len);
    if (hdr == NULL) {
        puts("error: packet buffer full");
        gnrc_pktbuf_release(pkt);
        return 1;
    }
    LL_PREPEND(pkt, hdr);
    nethdr = (gnrc_netif_hdr_t *)hdr->data;
    nethdr->flags = flags;

    while (1) {
        if (gnrc_netapi_send(dev, pkt) < 1) {
            puts("error: unable to send\n");
            gnrc_pktbuf_release(pkt);
            return 1;
        }
    }

    /* main thread exits */
    return 0;
}
