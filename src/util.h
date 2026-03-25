#ifndef UTIL_H
#define UTIL_H

#include <gnutls/gnutls.h>
#include <stddef.h>

#include "main.h"

void format_iso8601(char *buf, size_t buflen, const char *tz);

void wrap_log_str(char *out, size_t outlen, const char *in);

void log_access_write(struct worker_st *ws, const char *ts, const char *src_ip, int src_port, const char *sni, const char *ua, const char *path, int status);

void log_auth_write(struct worker_st *ws, const char *ts, const char *username, const char *src_ip, int src_port, int attempts);

void log_connection_write(main_server_st *s, struct proc_st *proc, const char *action);

const char *extract_sni_from_client_hello(uint8_t *buf, size_t len, char *out, size_t outlen);

const char *extract_host_from_buffer(uint8_t *buf, size_t len, char *out, size_t outlen);

#endif
