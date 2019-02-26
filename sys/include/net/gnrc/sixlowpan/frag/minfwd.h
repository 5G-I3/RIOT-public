/*
 * Copyright (C) 2019 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_gnrc_sixlowpan_frag_minfwd  Minimal fragment forwarding
 * @ingroup     net_gnrc_sixlowpan_frag
 * @brief       Provides minimal fragment forwarding using the VRB
 * @see         https://tools.ietf.org/html/draft-ietf-6lo-minimal-fragment-01
 * @see         @ref net_gnrc_sixlowpan_frag_vrb
 * @experimental
 * @{
 *
 * @file
 * @brief   Minimal fragment forwarding definitions
 *
 * @author  Martine Lenders <m.lenders@fu-berlin.de>
 */
#ifndef NET_GNRC_SIXLOWPAN_FRAG_MINFWD_H
#define NET_GNRC_SIXLOWPAN_FRAG_MINFWD_H

#include <stddef.h>

#include "net/gnrc/pkt.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/sixlowpan/frag.h"
#include "net/gnrc/sixlowpan/frag/vrb.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Generates a VRB entry from a given network layer header destination
 *          (based on FIB)
 *
 * @pre     `(hdr != NULL) && (hdr_len > 0)`
 * @pre     `hdr_len` must be correct for the @p hdr_type provided
 *          (e.g. `if (type == GNRC_NETTYPE_IPV6) => (hdr_len >= 40)`).
 * @pre     `base != NULL`
 *
 * @param[in] hdr           Header containing the destination to search a FIB
 *                          entry for. Must not be `NULL`.
 * @param[in] hdr_len       Length @p hdr. Must be > 0.
 * @param[in] hdr_type      Type of @p hdr.
 * @param[in] netif         Restrict route search to this interface.
 *                          May be `NULL` for any interface.
 * @param[in] base          Base data of the datagram. Must not be `NULL`.
 *
 * @return  A new VRB entry on success.
 * @return  NULL, if no route to the destination of @p hdr can be found (incl.
 *          if @p hdr_type is unknown), the destination of @p hdr is on this
 *          node, or if VRB is full.
 */
gnrc_sixlowpan_frag_vrb_t *gnrc_sixlowpan_frag_minfwd_vrbe_from_route(
        const void *hdr, size_t hdr_len, gnrc_nettype_t hdr_type,
        gnrc_netif_t *netif, const gnrc_sixlowpan_rbuf_base_t *base);

/**
 * @brief   Forwards a fragment according to a VRB entry
 *
 * @param[in,out] vrbe  A VRB entry. Must not be `NULL`.
 *                      gnrc_sixlowpan_frag_vrb_t::super::current_size will be
 *                      incremented by @p frag_size.
 *                      Will be removed from VRB when
 *                      gnrc_sixlowpan_frag_vrb_t::super::current_size is
 *                      greater or equal to
 *                      gnrc_sixlowpan_frag_vrb_t::super::datagram_size
 * @param[in] pkt       The fragment/packet to forward. Must not be `NULL`.
 *                      Must start with a fragment dispatch when
 *                      gnrc_pktsnip_t::type is GNRC_NETTYPE_SIXLOWPAN.
 *                      gnrc_pktsnip_t::next must either be `NULL` or its
 *                      gnrc_pktsnip_t::type must be GNRC_NETTYPE_NETIF.
 *                      Will be released on -ENOMEM. Must not be changed or
 *                      used by caller after success.
 * @param[in] frag_size The fragment's size (might differ from
 *                      gnrc_pktsnip_t::size of @p pkt) to update
 *                      gnrc_sixlowpan_frag_vrb_t::current_size with.
 * @param[in] page      Current 6Lo dispatch parsing page.
 *
 * @pre `vrbe != NULL`
 * @pre `pkt != NULL`
 * @pre When `(pkt->type == GNRC_NETTYPE_SIXLOWPAN)`, the gnrc_pktsnip_t::data
 *      points to a @ref sixlowpan_frag_t or @ref sixlowpan_frag_n_t.
 * @pre `(pkt->next == NULL) || (pkt->next->type == GNRC_NETTYPE_NETIF)`
 *
 * @return  0 on success.
 * @return  -ENOMEM, when packet buffer is too full to prepare packet for
 *          forwarding. @p pkt is released in that case.
 * @return  -EINVAL, when gnrc_pktsnip_t::type @p pkt is of an unexpected type
 *          (i.e. when it is not GNRC_NETTYPE_SIXLOWPAN and there is no header
 *          compression available). @p pkt is **NOT** released in that case.
 * @return  -ENOENT, when no @ref gnrc_sixlowpan_msg_frag_t can be allocated
 *          to forward a first (re-compressed) fragment. @p pkt is **NOT**
 *          released in that case.
 * @return  -ETIMEDOUT, when the hop-limit is reached. The packet should be
 *          reassembled and handled by the actual handler in case error
 *          messages are supposed to be sent.
 */
int gnrc_sixlowpan_frag_minfwd_forward(gnrc_sixlowpan_frag_vrb_t *vrbe,
                                       gnrc_pktsnip_t *pkt, size_t frag_size,
                                       unsigned page);

/**
 * @brief   Fragments a packet with just the IPHC (and padding payload to get
 *          to 8 byte) as the first fragment
 *
 * @pre `(frag_msg != NULL)`
 * @pre `(pkt != NULL) && (pkt->type == GNRC_NETTYPE_NETIF)`
 * @pre `(pkt->next != NULL) && (pkt->next->type == GNRC_NETTYPE_SIXLOWPAN)`
 *
 * @param[in] pkt                   The compressed packet to be sent. Must be in
 *                                  send order with a packet snip of type
 *                                  @ref GNRC_NETTYPE_NETIF first,
 *                                  @ref GNRC_NETTYPE_SIXLOWPAN (the IPHC
 *                                  header including NHC) second, and 0 or more
 *                                  snips of payload.
 * @param[in] orig_datagram_size    The size of the @p pkt before compression
 *                                  (without @ref GNRC_NETTYPE_NETIF snip).
 *                                  This can differ from @p frag_msg's
 *                                  gnrc_sixlowpan_msg_frag_t::datagram_size
 *                                  as it might just be a fragment in forwarding
 *                                  that is re-compressed in @p pkt.
 * @param[in] ipv6_addr             The (uncompressed) destination address of
 *                                  @p pkt.
 * @param[in] frag_msg              A @ref gnrc_sixlowpan_msg_frag_t object
 *
 * @return  0, when fragmentation was successful
 * @return  -1, on error. @p pkt is **not** released in that case and *should*
 *          be handled by normal fragmentation.
 */
int gnrc_sixlowpan_frag_minfwd_frag_iphc(gnrc_pktsnip_t *pkt,
                                         size_t orig_datagram_size,
                                         const ipv6_addr_t *ipv6_addr,
                                         gnrc_sixlowpan_msg_frag_t *frag_msg);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_SIXLOWPAN_FRAG_MINFWD_H */
/** @} */
