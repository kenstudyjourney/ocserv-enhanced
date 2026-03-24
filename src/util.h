#ifndef UTIL_H
#define UTIL_H

#include <gnutls/gnutls.h>
#include <stddef.h>

struct worker_st;

void format_iso8601(char *buf, size_t buflen, const char *tz);

void log_access_write(worker_st *ws, const char *ts, const char *src_ip, const char *sni, const char *ua, const char *path, int status);

const char *extract_sni_from_client_hello(uint8_t *buf, size_t len, char *out, size_t outlen);

const char *extract_host_from_buffer(uint8_t *buf, size_t len, char *out, size_t outlen);

#endif