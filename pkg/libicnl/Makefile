PKG_NAME=libICNL
PKG_URL=https://github.com/cgundogan/libICNL/
PKG_VERSION=23ae602a3af76493d951bf60b9de885108231914
PKG_LICENSE=LGPLv2.1

include $(RIOTBASE)/pkg/pkg.mk

all: $(BINDIR)/libicnl.a

$(BINDIR)/libicnl.a:
	git -C $(PKG_BUILDDIR) submodule update --init --recursive
	cd $(PKG_BUILDDIR)/build && cmake -DBUILD_TESTING=OFF .. && make && \
	cd lib && for l in *.a; do $(AR) x $$l; done && ar rcs libicnl.a *.obj
	cp $(PKG_BUILDDIR)/build/lib/libicnl.a $(BINDIR)/
