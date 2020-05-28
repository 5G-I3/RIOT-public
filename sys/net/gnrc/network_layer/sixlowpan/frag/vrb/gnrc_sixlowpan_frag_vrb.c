/*
 * Copyright (C) 2019 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 * @author  Martine Lenders <m.lenders@fu-berlin.de>
 */

#include "net/ieee802154.h"
#ifdef MODULE_GNRC_IPV6_NIB
#include "net/ipv6/addr.h"
#include "net/gnrc/ipv6/nib.h"
#endif  /* MODULE_GNRC_IPV6_NIB */
#ifdef MODULE_GNRC_ICNLOWPAN_HC
#include "ccn-lite-riot.h"
#include "ccnl-defs.h"
#include "ccnl-pkt-ndntlv.h"
#include "ccnl-pkt-util.h"
#undef DEBUG
#endif
#include "net/gnrc/netif.h"
#include "xtimer.h"

#include "net/gnrc/sixlowpan/frag/fb.h"
#ifdef  MODULE_GNRC_SIXLOWPAN_FRAG_STATS
#include "net/gnrc/sixlowpan/frag/stats.h"
#endif  /* MODULE_GNRC_SIXLOWPAN_FRAG_STATS */
#include "net/gnrc/sixlowpan/frag/vrb.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

static gnrc_sixlowpan_frag_vrb_t _vrb[CONFIG_GNRC_SIXLOWPAN_FRAG_VRB_SIZE];
#ifdef MODULE_GNRC_IPV6_NIB
static char addr_str[IPV6_ADDR_MAX_STR_LEN];
#else   /* MODULE_GNRC_IPV6_NIB */
static char addr_str[3 * IEEE802154_LONG_ADDRESS_LEN];
#endif  /* MODULE_GNRC_IPV6_NIB */

static inline bool _equal_index(const gnrc_sixlowpan_frag_vrb_t *vrbe,
                                const uint8_t *src, size_t src_len,
                                unsigned tag)
{
    return ((vrbe->super.tag == tag) &&
            (vrbe->super.src_len == src_len) &&
            (memcmp(vrbe->super.src, src, src_len) == 0));
}


gnrc_sixlowpan_frag_vrb_t *gnrc_sixlowpan_frag_vrb_add(
        const gnrc_sixlowpan_frag_rb_base_t *base,
        gnrc_netif_t *out_netif, const uint8_t *out_dst, size_t out_dst_len)
{
    gnrc_sixlowpan_frag_vrb_t *vrbe = NULL;

    assert(base != NULL);
    assert(out_netif != NULL);
    assert(out_dst != NULL);
    assert(out_dst_len > 0);
    for (unsigned i = 0; i < CONFIG_GNRC_SIXLOWPAN_FRAG_VRB_SIZE; i++) {
        gnrc_sixlowpan_frag_vrb_t *ptr = &_vrb[i];

        if (gnrc_sixlowpan_frag_vrb_entry_empty(ptr) ||
            _equal_index(ptr, base->src, base->src_len, base->tag)) {
            vrbe = ptr;
            if (gnrc_sixlowpan_frag_vrb_entry_empty(vrbe)) {
                vrbe->super = *base;
                vrbe->out_netif = out_netif;
                memcpy(vrbe->super.dst, out_dst, out_dst_len);
                vrbe->out_tag = gnrc_sixlowpan_frag_fb_next_tag();
                vrbe->super.dst_len = out_dst_len;
                DEBUG("6lo vrb: creating entry (%s, ",
                      gnrc_netif_addr_to_str(vrbe->super.src,
                                             vrbe->super.src_len,
                                             addr_str));
                DEBUG("%s, %u, %u) => ",
                      gnrc_netif_addr_to_str(vrbe->super.dst,
                                             vrbe->super.dst_len,
                                             addr_str),
                      (unsigned)vrbe->super.datagram_size, vrbe->super.tag);
                DEBUG("(%s, %u)\n",
                      gnrc_netif_addr_to_str(vrbe->super.dst,
                                             vrbe->super.dst_len,
                                             addr_str), vrbe->out_tag);
            }
            /* _equal_index() => append intervals of `base`, so they don't get
             * lost. We use append, so we don't need to change base! */
            else if (base->ints != NULL) {
                gnrc_sixlowpan_frag_rb_int_t *tmp = vrbe->super.ints;

                if (tmp != base->ints) {
                    /* base->ints is not already vrbe->super.ints */
                    if (tmp != NULL) {
                        /* iterate before appending and check if `base->ints` is
                         * not already part of list */
                        while (tmp->next != NULL) {
                            if (tmp == base->ints) {
                                tmp = NULL;
                                break;
                            }
                            tmp = tmp->next;
                        }
                        if (tmp != NULL) {
                            tmp->next = base->ints;
                        }
                    }
                    else {
                        vrbe->super.ints = base->ints;
                    }
                }
            }
            break;
        }
    }
#ifdef MODULE_GNRC_SIXLOWPAN_FRAG_STATS
    if (vrbe == NULL) {
        gnrc_sixlowpan_frag_stats_get()->vrb_full++;
    }
#endif
    return vrbe;
}

#ifdef MODULE_GNRC_ICNLOWPAN_HC
static struct ccnl_pkt_s *_preparse_ndn(const gnrc_pktsnip_t *pkt,
                                        uint64_t *pkt_type)
{
    struct ccnl_pkt_s *ccnl_pkt = NULL;
    uint8_t *start = pkt->data, *data = pkt->data;
    size_t size = pkt->size, field_len;

    /* XXX cannot use ccnl_ndntlv_dehead() and ccnl_ndntlv_bytes2pkt() as it
     * checks the length field against the actual length, so do it by hand */
    if ((ccnl_ndntlv_dehead_soft(&data, &size, pkt_type, &field_len) < 0) ||
        (((int)pkt->size - size) <= 0)) {
        DEBUG("6lo vrb NDN: unable to dehead packet\n");
        return NULL;
    }
    if (ccnl_ndntlv_bytes2pkt_partial(*pkt_type, start, data, size,
                                      &ccnl_pkt, 0, size) < 0) {
        DEBUG("6lo vrb NDN: no prefix found in packet\n");
        return NULL;
    }
    else if (ccnl_pkt) {
        if (ccnl_pkt->pfx) {
            return ccnl_pkt;
        }
        DEBUG("6lo vrb NDN: parsable packet, but name incomplete\n")
        ccnl_pkt_free(ccnl_pkt);
        return NULL;
    }
    DEBUG("6lo vrb NDN: packet not parsable\n");
    return NULL;
}
#endif


gnrc_sixlowpan_frag_vrb_t *gnrc_sixlowpan_frag_vrb_from_route(
            const gnrc_sixlowpan_frag_rb_base_t *base,
            gnrc_netif_t *netif, const gnrc_pktsnip_t *hdr)
{
    gnrc_sixlowpan_frag_vrb_t *res = NULL;

    assert(base != NULL);
    assert((hdr != NULL) && (hdr->data != NULL) && (hdr->size > 0));
    switch (hdr->type) {
#ifdef MODULE_GNRC_IPV6_NIB
        case GNRC_NETTYPE_IPV6: {
            assert(hdr->size >= sizeof(ipv6_hdr_t));
            const ipv6_addr_t *addr = &((const ipv6_hdr_t *)hdr->data)->dst;
            gnrc_ipv6_nib_nc_t nce;

            if (!ipv6_addr_is_link_local(addr) &&
                (gnrc_netif_get_by_ipv6_addr(addr) == NULL) &&
                (gnrc_ipv6_nib_get_next_hop_l2addr(addr, netif, NULL,
                                                   &nce) == 0)) {

                DEBUG("6lo vrb: FIB entry for IPv6 destination %s found\n",
                      ipv6_addr_to_str(addr_str, addr, sizeof(addr_str)));
                res = gnrc_sixlowpan_frag_vrb_add(
                        base,
                        gnrc_netif_get_by_pid(gnrc_ipv6_nib_nc_get_iface(&nce)),
                        nce.l2addr, nce.l2addr_len
                    );
            }
            else {
                DEBUG("6lo vrb: no FIB entry for IPv6 destination %s found\n",
                      ipv6_addr_to_str(addr_str, addr, sizeof(addr_str)));
            }
            break;
        }
#endif  /* MODULE_GNRC_IPV6_NIB */
#ifdef MODULE_GNRC_ICNLOWPAN_HC
        case GNRC_NETTYPE_CCN: {
            assert((ccnl_pkt2suite(hdr->data, hdr->size, NULL)
                    == CCNL_SUITE_NDNTLV) && (hdr->size > 1));
            uint64_t type;
            struct ccnl_pkt_s *ccnl_pkt;

            ccnl_pkt = _preparse_ndn(hdr, &type);
            if (!ccnl_pkt) {
                DEBUG("6lo vrb: unable to find NDN prefix\n");
                break;
            }
            DEBUG("6lo vrb: Found prefix %s in packet\n",
                  ccnl_prefix_to_str(ccnl_pkt->pfx, addr_str,
                                     sizeof(addr_str)));
            switch (type) {
                case NDN_TLV_Interest: {
                    struct ccnl_forward_s *fwd;

                    for (fwd = ccnl_relay.fib; fwd; fwd = fwd->next) {
                        int rc;

                        if (!fwd->prefix) {
                            continue;
                        }
                        rc = ccnl_prefix_cmp(fwd->prefix, NULL, ccnl_pkt->pfx,
                                             CMP_LONGEST);

                        DEBUG("6lo vrb: rc=%ld/%ld\n", (long)rc,
                              (long)fwd->prefix->compcnt);
                        if (rc < (signed)fwd->prefix->compcnt) {
                            continue;
                        }
                        DEBUG("6lo vrb: FIB entry for prefix %s found\n",
                              ccnl_prefix_to_str(ccnl_pkt->pfx,
                                                 addr_str, sizeof(addr_str)));
                        assert(fwd->face->peer.sa.sa_family == AF_PACKET);
                        res = gnrc_sixlowpan_frag_vrb_add(
                                base,
                                gnrc_netif_get_by_pid(ccnl_relay.ifs[0].if_pid),
                                fwd->face->peer.linklayer.sll_addr,
                                fwd->face->peer.linklayer.sll_halen
                            );
                        break;
                    }
                    break;
                }
                case NDN_TLV_Data: {
                    struct ccnl_interest_s *i;

                    for (i = ccnl_relay.pit; i; i = i->next) {
                        struct ccnl_pendint_s *pi;

                        /* TODO: CCNL_FACE_FLAGS_SERVED stuff?
                         *       see ccnl_content_serve_pending() */
                        /* XXX or rather ccnl_i_prefixof_c()? */
                        if (ccnl_prefix_cmp(i->pkt->pfx, NULL, ccnl_pkt->pfx,
                                            CMP_EXACT) < 0) {
                            // XX must also check i->ppkl,
                            continue;
                        }
                        for (pi = i->pending; pi; pi = pi->next) {
                            if (pi->face->ifndx >= 0) {
                                kernel_pid_t if_pid = ccnl_relay.ifs[0].if_pid;
                                DEBUG("6lo vrb: PIT entry for prefix %s found\n",
                                      ccnl_prefix_to_str(ccnl_pkt->pfx, addr_str,
                                                         sizeof(addr_str)));
                                assert(pi->face->peer.sa.sa_family == AF_PACKET);
                                res = gnrc_sixlowpan_frag_vrb_add(
                                        base,
                                        gnrc_netif_get_by_pid(if_pid),
                                        pi->face->peer.linklayer.sll_addr,
                                        pi->face->peer.linklayer.sll_halen
                                    );
                                break;
                            }
                        }
                    }
                    break;
                }
                default:
                    DEBUG("6lo vrb: Do not know how forward packet type %u\n",
                          (unsigned)type);
                    break;
            }
            ccnl_pkt_free(ccnl_pkt);
            break;
        }
#endif
        default:
            (void)base;
            (void)netif;
            DEBUG("6lo vrb: unknown forwarding header type %d\n", hdr->type);
            break;
    }
    return res;
}

gnrc_sixlowpan_frag_vrb_t *gnrc_sixlowpan_frag_vrb_get(
        const uint8_t *src, size_t src_len, unsigned src_tag)
{
    DEBUG("6lo vrb: trying to get entry for (%s, %u)\n",
          gnrc_netif_addr_to_str(src, src_len, addr_str), src_tag);
    for (unsigned i = 0; i < CONFIG_GNRC_SIXLOWPAN_FRAG_VRB_SIZE; i++) {
        gnrc_sixlowpan_frag_vrb_t *vrbe = &_vrb[i];

        if (_equal_index(vrbe, src, src_len, src_tag)) {
            DEBUG("6lo vrb: got VRB to (%s, %u)\n",
                  gnrc_netif_addr_to_str(vrbe->super.dst,
                                         vrbe->super.dst_len,
                                         addr_str), vrbe->out_tag);
            return vrbe;
        }
    }
    DEBUG("6lo vrb: no entry found\n");
    return NULL;
}

gnrc_sixlowpan_frag_vrb_t *gnrc_sixlowpan_frag_vrb_reverse(
        const gnrc_netif_t *netif, const uint8_t *src, size_t src_len,
        unsigned tag)
{
    DEBUG("6lo vrb: trying to get entry for reverse label switching (%s, %u)\n",
          gnrc_netif_addr_to_str(src, src_len, addr_str), tag);
    for (unsigned i = 0; i < CONFIG_GNRC_SIXLOWPAN_FRAG_VRB_SIZE; i++) {
        gnrc_sixlowpan_frag_vrb_t *vrbe = &_vrb[i];

        if ((vrbe->out_tag == tag) && (vrbe->out_netif == netif) &&
            (memcmp(vrbe->super.dst, src, src_len) == 0)) {
            DEBUG("6lo vrb: got VRB entry from (%s, %u)\n",
                  gnrc_netif_addr_to_str(vrbe->super.src,
                                         vrbe->super.src_len,
                                         addr_str), vrbe->super.tag);
            return vrbe;
        }
    }
    DEBUG("6lo vrb: no entry found\n");
    return NULL;

}

void gnrc_sixlowpan_frag_vrb_gc(void)
{
    uint32_t now_usec = xtimer_now_usec();

    for (unsigned i = 0; i < CONFIG_GNRC_SIXLOWPAN_FRAG_VRB_SIZE; i++) {
        if (!gnrc_sixlowpan_frag_vrb_entry_empty(&_vrb[i]) &&
            (now_usec - _vrb[i].super.arrival) > CONFIG_GNRC_SIXLOWPAN_FRAG_VRB_TIMEOUT_US) {
            DEBUG("6lo vrb: entry (%s, ",
                  gnrc_netif_addr_to_str(_vrb[i].super.src,
                                         _vrb[i].super.src_len,
                                         addr_str));
            DEBUG("%s, %u, %u) timed out\n",
                  gnrc_netif_addr_to_str(_vrb[i].super.dst,
                                         _vrb[i].super.dst_len,
                                         addr_str),
                  (unsigned)_vrb[i].super.datagram_size, _vrb[i].super.tag);
            gnrc_sixlowpan_frag_vrb_rm(&_vrb[i]);
        }
    }
}

#ifdef TEST_SUITES
void gnrc_sixlowpan_frag_vrb_reset(void)
{
    memset(_vrb, 0, sizeof(_vrb));
}
#endif

/** @} */
