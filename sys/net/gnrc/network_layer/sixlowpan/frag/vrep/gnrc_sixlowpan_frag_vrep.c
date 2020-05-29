/*
 * Copyright (C) 2020 Freie Universität Berlin
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

#ifdef MODULE_CCN_LITE
#include "ccn-lite-riot.h"
#undef DEBUG
#endif
#include "net/gnrc/nettype.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/sixlowpan/frag/rb.h"
#include "net/sixlowpan.h"
#include "net/sixlowpan/sfr.h"
#include "od.h"
#include "utlist.h"

#include "net/gnrc/sixlowpan/frag/vrep.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

uint8_t _tag(sixlowpan_sfr_t *frag)
{
    return frag->tag;
}

void gnrc_sixlowpan_frag_vrep_del_store(void *arg)
{
    gnrc_sixlowpan_frag_vrb_t *vrbe = arg;
    vrbe->store = NULL;
    while (vrbe->super.ints) {
        LL_DELETE(vrbe->super.ints, vrbe->super.ints);
    }
}

void gnrc_sixlowpan_frag_vrep_log_frag(gnrc_sixlowpan_frag_vrb_t *vrbe,
                                       gnrc_sixlowpan_frag_rb_int_t *frag_int,
                                       gnrc_pktsnip_t *frag)
{
    uint8_t *data = frag->data;
    uint16_t frag_size;
    uint16_t offset;

    assert((frag->type == GNRC_NETTYPE_SIXLOWPAN) &&
           sixlowpan_sfr_rfrag_is(frag->data));
    frag_int->seq = sixlowpan_sfr_rfrag_get_seq(frag->data);
    if (frag_int->seq && !vrbe->store) {
        DEBUG("vrep: No VREP entry\n");
        return;
    }
    data += sizeof(sixlowpan_sfr_rfrag_t);
    frag_size = sixlowpan_sfr_rfrag_get_frag_size(frag->data);
    offset = sixlowpan_sfr_rfrag_get_offset(frag->data);
#if IS_USED(MODULE_CCN_LITE)
    struct ccnl_pkt_s *pkt;
    struct ccnl_content_s *c = vrbe->store;

    if (frag_int->seq > 0) {
        pkt = c->pkt;

        if (ccnl_ndntlv_bytes2pkt_partial(pkt->type, data, data, frag_size,
                                          &pkt, offset,
                                          vrbe->super.datagram_size) < 0) {
            DEBUG("vrep: unable to add further payloads");
            goto error_out;
        }
    }
    else if (c && !offset && !frag_size) {
        c->del_cb = NULL;
        c->del_cb_ctx = NULL;
        gnrc_sixlowpan_frag_vrep_del_store(vrbe);
        goto error_out;
    }
    else {
        uint64_t type;
        size_t size = frag_size, field_len;
        uint8_t *start = data;

        if ((ccnl_ndntlv_dehead_soft(&data, &size, &type, &field_len) < 0) ||
            (((int)frag_size - size) <= 0)) {
            DEBUG("vrep: unable to dehead packet\n");
            goto error_out;
        }
        if (c == NULL) {
            pkt = NULL;
        }
        else {
            pkt = c->pkt;
        }
        if (ccnl_ndntlv_bytes2pkt_partial(type, start, data, size,
                                          &pkt, 0, vrbe->super.datagram_size) < 0) {
            DEBUG("vrep: unable to parse first fragment\n");
            goto error_out;
        }
        else if ((vrbe->store == NULL) && pkt) {
            struct ccnl_content_s *c, *cs;

            pkt->type = type;

            c = ccnl_content_new(&pkt);
            if (c == NULL) {
                DEBUG("vrep: unable to create content entry\n");
                ccnl_pkt_free(pkt);
                goto error_out;
            }
            if ((cs = ccnl_content_add2cache(
                    &ccnl_relay, c
                 ))) {
                vrbe->store = cs;
                cs->del_cb = gnrc_sixlowpan_frag_vrep_del_store;
                cs->del_cb_ctx = vrbe;
            }
            else {
                DEBUG("vrep: unable to add TENTATIVE packet to cache\n");
                ccnl_content_free(c);
                goto error_out;
            }
            if (ENABLE_DEBUG) {
                pkt = cs->pkt;
            }
        }
#endif
    }
    if (ENABLE_DEBUG && IS_USED(MODULE_OD)) {
        DEBUG("Current datagram %u (%u/%u bytes, datalen: %u):\n",
              vrbe->super.tag, vrbe->super.current_size,
              vrbe->super.datagram_size, (unsigned)pkt->buf->datalen);
        od_hex_dump(pkt->buf->data, pkt->buf->datalen, OD_WIDTH_DEFAULT);
    }
    frag_int->ack_req = sixlowpan_sfr_rfrag_ack_req(frag->data);
    frag_int->ecn = sixlowpan_sfr_ecn(frag->data);
    vrbe->super.current_size += frag_size;
    return;
error_out:
    frag_int->start = 0;
    frag_int->end = 0;
    LL_DELETE(vrbe->super.ints, frag_int);
    frag_int->next = NULL;
}

gnrc_pktsnip_t *gnrc_sixlowpan_frag_vrep_get_frag(
        gnrc_sixlowpan_frag_vrb_t *vrbe,
        gnrc_sixlowpan_frag_rb_int_t *frag_int)
{
    size_t size = frag_int->end - frag_int->start + 1;
    gnrc_pktsnip_t *frag = gnrc_pktbuf_add(NULL, NULL,
                                           sizeof(sixlowpan_sfr_rfrag_t) +
                                           size, GNRC_NETTYPE_SIXLOWPAN);

    if (frag) {
        sixlowpan_sfr_rfrag_t *hdr;
        uint16_t offset;
        uint8_t *data;

        sixlowpan_sfr_rfrag_set_disp(frag->data);
        hdr = frag->data;
        hdr->base.tag = vrbe->super.tag;
        if (frag_int->ack_req) {
            sixlowpan_sfr_rfrag_set_ack_req(hdr);
        }
        else {
            sixlowpan_sfr_rfrag_clear_ack_req(hdr);
        }
        sixlowpan_sfr_rfrag_set_frag_size(hdr, size);
        sixlowpan_sfr_rfrag_set_seq(hdr, frag_int->seq);
        if (frag_int->start) {
            sixlowpan_sfr_rfrag_set_offset(frag->data, frag_int->start);
            offset = frag_int->start;
        }
        else {
            sixlowpan_sfr_rfrag_set_offset(frag->data,
                                           vrbe->super.datagram_size);
            offset = 0;
        }
        data = (uint8_t *)(hdr + 1);
#if IS_USED(MODULE_CCN_LITE)
        if (vrbe->store) {
            struct ccnl_pkt_s *pkt = ((struct ccnl_content_s *)vrbe->store)->pkt;

            assert(pkt->buf->data);
            memcpy(data, &pkt->buf->data[offset], frag_int->end - frag_int->start);
        }
#else
        (void)data;
#endif
        if (ENABLE_DEBUG && IS_USED(MODULE_OD)) {
            puts("Created fragment:");
            od_hex_dump(frag->data, frag->size, OD_WIDTH_DEFAULT);
        }
        else {
            DEBUG("Created fragment seq=%u of datagram tag=%u\n",
                  frag_int->seq, vrbe->super.tag);
        }
    }
    return frag;
}

void gnrc_sixlowpan_frag_vrep_reass(gnrc_sixlowpan_frag_vrb_t *vrbe)
{
    if (vrbe->store == NULL) {
        return;
    }
#if IS_USED(MODULE_CCN_LITE)
    static char s[CCNL_MAX_PREFIX_SIZE];
    struct ccnl_pkt_s *pkt = ((struct ccnl_content_s *)vrbe->store)->pkt;
    struct ccnl_interest_s *i;

    if (ENABLE_DEBUG) {
        ccnl_prefix_to_str(pkt->pfx, s, CCNL_MAX_PREFIX_SIZE);
    }

    DEBUG("6lo vrep: remove TENTATIVE mark for pkt=%p (%s)\n", pkt, s);
    pkt->flags &= ~CCNL_PKT_TENTATIVE;

    if (ENABLE_DEBUG && IS_USED(MODULE_OD)) {
        DEBUG("Completed packet (%u bytes):\n", pkt->buf->datalen);
        od_hex_dump(pkt->buf->data, pkt->buf->datalen, OD_WIDTH_DEFAULT);
    }

    DEBUG("6lo vrep: search for pending interests of content %s\n", s);
    for (i = ccnl_relay.pit; i; i = i->next) {
        if (ccnl_interest_isSame(i, pkt)) {
            break;
        }
    }
    if (i != NULL) {
        msg_t msg = { .type = CCNL_MSG_INT_TIMEOUT, .content.ptr = i };
        if (msg_try_send(&msg, ccnl_event_loop_pid) < 1) {
            DEBUG("6lo vrep: interest not removed; message queue full");
        }
        else {
            DEBUG("6lo vrep: interest removed\n");
        }
    }
    else {
        DEBUG("6lo vrep: no pending interest found\n");
    }
#endif
    return;
}
