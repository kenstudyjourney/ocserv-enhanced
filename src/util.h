#ifndef UTIL_H
#define UTIL_H

#include <gnutls/gnutls.h>
#include <stddef.h>

struct worker_st;

void format_iso8601(char *buf, size_t buflen, const char *tz);

void log_access_write(worker_st *ws, const char *ts, const char *src_ip, const char *sni, const char *ua, const char *path, int status);

#endif