/*
 * Copyright (C) 2020 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_gnrc_sixlowpan_frag_vrep 6LoWPAN virtual reassembling endpoint
 * @ingroup     net_gnrc_sixlowpan_frag
 * @brief       6LoWPAN virtual reassembling endpoint for fragment forwarding
 *
 * @{
 *
 * @file
 * @brief   6LoWPAN virtual reassembling endpoint definitions
 *
 * @author  Martine Lenders <m.lenders@fu-berlin.de>
 */
#ifndef NET_GNRC_SIXLOWPAN_FRAG_VREP_H
#define NET_GNRC_SIXLOWPAN_FRAG_VREP_H

#include <stdbool.h>

#include "kernel_defines.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/sixlowpan/frag/rb.h"
#include "net/gnrc/sixlowpan/frag/vrb.h"
#include "net/sixlowpan/sfr.h"

#if IS_USED(MODULE_CCN_LITE)
#include "ccn-lite-riot.h"
#undef DEBUG
#endif

#ifdef __cplusplus
extern "C" {
#endif

static inline bool gnrc_sixlowpan_frag_vrep_is(
        const gnrc_sixlowpan_frag_vrb_t *entry)
{
#if IS_USED(MODULE_GNRC_SIXLOWPAN_FRAG_VREP)
    return (entry->store != NULL);
#else
    (void)entry;
    return false;
#endif
}

static inline bool gnrc_sixlowpan_frag_vrep_complete(
        const gnrc_sixlowpan_frag_rb_base_t *entry)
{
    return (entry->current_size == entry->datagram_size);
}

void gnrc_sixlowpan_frag_vrep_del_store(void *arg);

void gnrc_sixlowpan_frag_vrep_log_frag(gnrc_sixlowpan_frag_vrb_t *vrbe,
                                       gnrc_sixlowpan_frag_rb_int_t *frag_int,
                                       gnrc_pktsnip_t *frag);

gnrc_pktsnip_t *gnrc_sixlowpan_frag_vrep_get_frag(
        gnrc_sixlowpan_frag_vrb_t *vrbe,
        gnrc_sixlowpan_frag_rb_int_t *frag_int);

void gnrc_sixlowpan_frag_vrep_reass(gnrc_sixlowpan_frag_vrb_t *entry);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_SIXLOWPAN_FRAG_VREP_H */
