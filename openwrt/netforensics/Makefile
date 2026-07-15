#
# OpenWrt package skeleton for forensicsd (CPE side).
# Place under package/feeds/... or copy into a local feed.
#
# Cross-compile notes:
#  - Build libnetdiag (nfct + nl80211_parse only) as a static dep, or
#    vendor the two .c files into this package for a smaller MIPS/ARM image.
#  - Prefer -Os -ffunction-sections -fdata-sections -Wl,--gc-sections.
#  - Fixed stack buffers already; avoid heap on event path in future hardening.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=netforensics-cpe
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=whitehse
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/netforensics-cpe
  SECTION:=net
  CATEGORY:=Network
  TITLE:=CPE conntrack/Wi-Fi forensics NDJSON emitter
  DEPENDS:=+libpthread
endef

define Package/netforensics-cpe/description
  forensicsd: AF_NETLINK conntrack + optional nl80211 station dump to NDJSON.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	# Expect sources synced into PKG_BUILD_DIR by the feed packaging step.
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -std=c11 -Wall -Wextra \
		-I$(PKG_BUILD_DIR)/include \
		-o $(PKG_BUILD_DIR)/forensicsd \
		$(PKG_BUILD_DIR)/cpe/forensicsd.c \
		$(PKG_BUILD_DIR)/src/*.c \
		$(PKG_BUILD_DIR)/deps/nfct.c \
		$(PKG_BUILD_DIR)/deps/nl80211_parse.c
endef

define Package/netforensics-cpe/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/forensicsd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/sysctl.d
	$(INSTALL_DATA) ./files/99-forensics.conf $(1)/etc/sysctl.d/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/forensicsd.init $(1)/etc/init.d/forensicsd
endef

$(eval $(call BuildPackage,netforensics-cpe))
