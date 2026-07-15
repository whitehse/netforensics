# OpenWrt packaging

## Layout

```
openwrt/netforensics/
  Makefile              # package definition (skeleton)
  files/
    99-forensics.conf   # symlink or copy from cpe/sysctl/
    forensicsd.init     # procd init
```

## Cross-compile tips

1. **Static deps**: copy `libnetdiag` `nfct.c` + `nl80211_parse.c` (+ headers)
   into the package `deps/` so the CPE image does not need a shared lib.
2. **Flags**: `-Os -ffunction-sections -fdata-sections` and link with
   `-Wl,--gc-sections` for MIPS/ARM flash budgets.
3. **Capabilities**: OpenWrt procd can grant `CAP_NET_ADMIN` via
   `procd_set_param capabilities` or run as root on small CPE.
4. **Vector agent**: point a local Vector (or syslog) at forensicsd stdout.

## Host build check

```bash
cmake -B build -S ../..
cmake --build build --target forensicsd
./build/forensicsd --demo --router-id lab-1
```
