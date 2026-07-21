/**
 * @file cpe_spool.h
 * @brief Shared spool paths / caps for cpe_agent + forensicsd (F6).
 *
 * Production still NDJSON → Vector (ADR-002). Both daemons may write under
 * the same directory; different filenames avoid interleave corruption.
 */
#ifndef CPE_SPOOL_H
#define CPE_SPOOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default directory for dual-daemon NDJSON on OpenWrt. */
#define CPE_SPOOL_DIR_DEFAULT "/var/spool/netforensics"

/** Default agent perf file under CPE_SPOOL_DIR_DEFAULT. */
#define CPE_SPOOL_PERF_DEFAULT "/var/spool/netforensics/cpe_perf.ndjson"

/** Default forensicsd NAT/wifi file under CPE_SPOOL_DIR_DEFAULT. */
#define CPE_SPOOL_FORENSICS_DEFAULT "/var/spool/netforensics/forensics.ndjson"

/** Soft cap for MIPS/ARM flash/RAM budgets (ring lines). */
#define CPE_SPOOL_MAX_LINES_OPENWRT 128

/** Hard upper bound for in-memory ring (validate). */
#define CPE_SPOOL_MAX_LINES_HARD 1024

/**
 * Ensure parent directories exist for @p file_path (mkdir -p style).
 * Does not create the file itself. @return 0 ok, -1 on error.
 */
int cpe_spool_ensure_parent_dir(const char *file_path);

/**
 * Ensure @p dir exists (mkdir -p). @return 0 ok, -1 on error.
 */
int cpe_spool_ensure_dir(const char *dir);

#ifdef __cplusplus
}
#endif

#endif /* CPE_SPOOL_H */
