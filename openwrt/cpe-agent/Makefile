#
# OpenWrt package skeleton for cpe_agent (Track 2 / P2.9).
# Place under package/feeds/... or copy into a local feed.
#
# Cross-compile notes:
#  - Vendor libnetdiag ping.c + nfct.c (+ headers) and libyaml src into deps/
#    so the image does not need shared sibling libs.
#  - libuv is a DEPENDS (OpenWrt package libuv).
#  - Prefer -Os -ffunction-sections -fdata-sections -Wl,--gc-sections.
#  - Do NOT package lab-only ClickHouse client flags for field images.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=cpe-agent
PKG_VERSION:=0.3.0
PKG_RELEASE:=1

PKG_MAINTAINER:=whitehse
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/cpe-agent
  SECTION:=net
  CATEGORY:=Network
  TITLE:=CPE performance agent (cpe_perf NDJSON)
  DEPENDS:=+libuv +libpthread
endef

define Package/cpe-agent/description
  cpe_agent: libuv host emitting type=cpe_perf NDJSON for Vector/ClickHouse.
  Co-exists with netforensics-cpe (forensicsd). No direct ClickHouse client.
endef

define Package/cpe-agent/conffiles
/etc/cpe_agent/cpe_agent.yaml
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	# Expect sources synced into PKG_BUILD_DIR by the feed packaging step.
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -std=c11 -Wall -Wextra \
		-I$(PKG_BUILD_DIR)/include \
		-I$(PKG_BUILD_DIR)/deps/include \
		-DCPE_AGENT_OPENWRT=1 \
		-o $(PKG_BUILD_DIR)/cpe_agent \
		$(PKG_BUILD_DIR)/agent/*.c \
		$(PKG_BUILD_DIR)/src/flow_correlate.c \
		$(PKG_BUILD_DIR)/deps/ping.c \
		$(PKG_BUILD_DIR)/deps/nfct.c \
		$(PKG_BUILD_DIR)/deps/netdiag.c \
		$(PKG_BUILD_DIR)/deps/yaml.c \
		-luv
endef

define Package/cpe-agent/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cpe_agent $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/cpe_agent
	$(INSTALL_DATA) ./files/cpe_agent.yaml $(1)/etc/cpe_agent/cpe_agent.yaml
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/cpe_agent.init $(1)/etc/init.d/cpe_agent
endef

$(eval $(call BuildPackage,cpe-agent))
