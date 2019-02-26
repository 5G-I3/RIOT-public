include ../Makefile.tests_common

USEMODULE += gnrc_ipv6_router_default
USEMODULE += gnrc_sixlowpan_frag_minfwd
USEMODULE += gnrc_sixlowpan_iphc
USEMODULE += gnrc_ipv6_nib
USEMODULE += gnrc_netif
USEMODULE += embunit
USEMODULE += netdev_ieee802154
USEMODULE += netdev_test

CFLAGS += -DTEST_SUITES
# disable router solicitations so they don't interfere with the tests
CFLAGS += -DGNRC_IPV6_NIB_CONF_NO_RTR_SOL=1

include $(RIOTBASE)/Makefile.include
