include ../Makefile.tests_common

BOARD_INSUFFICIENT_MEMORY := # TODO

USEMODULE += gnrc_ipv6_router_default
USEMODULE += gnrc_sixlowpan_frag_minfwd
USEMODULE += gnrc_sixlowpan_iphc
USEMODULE += gnrc_ipv6_nib
USEMODULE += gnrc_netif
USEMODULE += embunit
USEMODULE += netdev_ieee802154
USEMODULE += netdev_test

CFLAGS += -D"TEST_SUITES"

# to be able to include gnrc_sixlowpan_frag-internal `rbuf.h`
INCLUDES += -I$(RIOTBASE)/sys/net/gnrc/network_layer/sixlowpan/frag/

TEST_ON_CI_WHITELIST += all

include $(RIOTBASE)/Makefile.include
