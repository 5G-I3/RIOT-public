include ../Makefile.tests_common

USEMODULE += gnrc_ipv6_router_default
USEMODULE += gnrc_sixlowpan_frag_sfr
USEMODULE += gnrc_sixlowpan_iphc
USEMODULE += gnrc_ipv6_nib
USEMODULE += gnrc_netif
USEMODULE += embunit
USEMODULE += netdev_ieee802154
USEMODULE += netdev_test

CFLAGS += -DTEST_SUITES
# disable router solicitations so they don't interfere with the tests
CFLAGS += -DGNRC_IPV6_NIB_CONF_NO_RTR_SOL=1
# fix window size
CFLAGS += -DGNRC_SIXLOWPAN_SFR_OPT_WIN_SIZE=3U
# decrease inter frame gap
CFLAGS += -DGNRC_SIXLOWPAN_SFR_INTER_FRAME_GAP_US=5U
# decrease minimal ARQ timeout
CFLAGS += -DGNRC_SIXLOWPAN_SFR_MIN_ARQ_TIMEOUT_MS=100U
# decrease initial ARQ timeout
CFLAGS += -DGNRC_SIXLOWPAN_SFR_OPT_ARQ_TIMEOUT_MS=100U

include $(RIOTBASE)/Makefile.include
