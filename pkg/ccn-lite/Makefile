PKG_NAME=ccn-lite
PKG_URL=git@github.com:5G-I3/ccn-lite-public.git
PKG_VERSION=52e92e7cd5ad0c8bd0dd1ee4c13bb65685924f43
PKG_LICENSE=ISC

include $(RIOTBASE)/pkg/pkg.mk

.PHONY: ..cmake_version_supported FORCE

CMAKE_MINIMAL_VERSION = 3.6.0

RIOT_CFLAGS = $(INCLUDES)

ifeq (llvm,$(TOOLCHAIN))
  RIOT_CFLAGS += -Wno-char-subscripts
endif

TOOLCHAIN_FILE = $(PKG_BUILDDIR)/xcompile-toolchain.cmake

all: $(BINDIR)/ccn-lite.a

$(BINDIR)/ccn-lite.a: $(PKG_BUILDDIR)/bin/lib/libccnl-riot.a
	cp $< $@

$(PKG_BUILDDIR)/bin/lib/libccnl-riot.a: $(PKG_BUILDDIR)/bin/Makefile
	$(MAKE) -C $(PKG_BUILDDIR)/bin

$(PKG_BUILDDIR)/bin/Makefile: $(PKG_PREPARED) $(TOOLCHAIN_FILE) | ..cmake_version_supported
	cmake -B$(PKG_BUILDDIR)/bin -H$(PKG_BUILDDIR)/src \
	      -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN_FILE) \
	      -DCCNL_RIOT=1 -DRIOT_CFLAGS="$(RIOT_CFLAGS)" -DBUILD_TESTING=OFF

$(TOOLCHAIN_FILE): FORCE
	$(RIOTTOOLS)/cmake/generate-xcompile-toolchain.sh > $(TOOLCHAIN_FILE)

..cmake_version_supported:
	@ # Remove '-rcX' from version as they are not well handled
	$(Q)\
	CMAKE_VERSION=$$(cmake --version | sed -n '1 {s/cmake version //;s/-rc.*//;p;}'); \
	$(RIOTTOOLS)/has_minimal_version/has_minimal_version.sh "$${CMAKE_VERSION}" "$(CMAKE_MINIMAL_VERSION)" cmake

ifneq (,$(filter -Wformat-nonliteral -Wformat=2, $(CFLAGS)))
  CFLAGS += -Wno-format-nonliteral
endif
