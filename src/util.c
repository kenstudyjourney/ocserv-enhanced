#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <gnutls/gnutls.h>

#include "main.h"
#include "vpn.h"
#include "worker.h"
#include "tlslib.h"
#include "common.h"
#include "ip-lease.h"

void format_iso8601(char *buf, size_t buflen, const char *tz)
{
    struct timeval tv;
    struct tm tm;
    char tzbuf[16] = {0};

    gettimeofday(&tv, NULL);

    /* set timezone */
    if (tz && tz[0]) {
        setenv("TZ", tz, 1);
        tzset();
    }

    localtime_r(&tv.tv_sec, &tm);

    /* format timezone offset like +08:00 */
    strftime(tzbuf, sizeof(tzbuf), "%z", &tm);

    /* insert colon in timezone (+0800 -> +08:00) */
    char tzfmt[8];
    snprintf(tzfmt, sizeof(tzfmt), "%c%c%c:%c%c",
        tzbuf[0], tzbuf[1], tzbuf[2], tzbuf[3], tzbuf[4]);

    snprintf(buf, buflen,
        "%04d-%02d-%02dT%02d:%02d:%02d.%06ld%s",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        (long)tv.tv_usec,
        tzfmt);
}

/**
 * wrap_log_str - copy input into buf, wrapping in quotes if necessary
 * and replacing \r or \n with literal \r and \n.
 *
 * @out: output buffer
 * @outlen: size of output buffer
 * @in: input string
 */
static const char *wrap_log_str(char *buf, size_t buflen, const char *str) {
    if (!str) str = "";

    int needs_quote = 0;
    size_t i, j = 0;

    // Determine if we need quotes (empty or contains space/tab/\r/\n)
    if (str[0] == '\0') {
        needs_quote = 1;
    } else {
        for (i = 0; str[i] != '\0'; i++) {
            if (isspace((unsigned char)str[i])) {
                needs_quote = 1;
                break;
            }
        }
    }

    if (!needs_quote) {
        // Copy as-is
        strncpy(buf, str, buflen - 1);
        buf[buflen - 1] = '\0';
        return buf;
    }

    // Wrap in quotes and escape line breaks
    if (buflen < 3) { // enough for ""\0
        if (buflen > 0) buf[0] = '\0';
        return buf;
    }

    buf[0] = '"';
    j = 1;
    for (i = 0; str[i] != '\0' && j < buflen - 1; i++) {
        if (str[i] == '\r') {
            if (j + 2 < buflen - 1) {
                buf[j++] = '\\';
                buf[j++] = 'r';
            } else break;
        } else if (str[i] == '\n') {
            if (j + 2 < buflen - 1) {
                buf[j++] = '\\';
                buf[j++] = 'n';
            } else break;
        } else {
            buf[j++] = str[i];
        }
    }
    buf[j++] = '"';
    buf[j] = '\0';

    return buf;
}

void log_access_write(worker_st *ws, const char *ts, const char *src_ip, int src_port, const char *sni, const char *ua, const char *path, int status)
{
    const char *dir = WSCONFIG(ws)->log_access_dir;

    /* disabled if empty */
    if (!dir || dir[0] == '\0')
        return;

    /* === build filename: access_YYYYMM.log === */
    char filepath[512];
    time_t now = time(NULL);
    struct tm tm;

    localtime_r(&now, &tm);

    snprintf(filepath, sizeof(filepath),
             "%s/access_%04d%02d.log",
             dir,
             tm.tm_year + 1900,
             tm.tm_mon + 1);

    /* === open file (append, create if needed) === */
    int fd = open(filepath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        return;

    /* === build log line === */
    char line[2048];

    char sni_wrapped[256];
    char ua_wrapped[256];
    char path_wrapped[512];

    wrap_log_str(sni_wrapped, sizeof(sni_wrapped), sni ? sni : "");
    wrap_log_str(ua_wrapped, sizeof(ua_wrapped), ua ? ua : "");
    wrap_log_str(path_wrapped, sizeof(path_wrapped), path ? path : "");

    int len = snprintf(line, sizeof(line),
        "[%s] %s %d %s %s %s %03d\n",
        ts,
        src_ip ? src_ip : "",
        src_port,
        sni_wrapped,
        ua_wrapped,
        path_wrapped,
        status);

    if (len > 0) {
        write(fd, line, len);
    }

    close(fd);
}

void log_auth_write(worker_st *ws, const char *ts, const char *username, const char *src_ip, int src_port, int attempts)
{
    const char *dir = WSCONFIG(ws)->log_auth_dir;

    /* disabled if empty */
    if (!dir || dir[0] == '\0')
        return;

    /* === build filename: authfail_YYYYMM.log === */
    char filepath[512];
    time_t now = time(NULL);
    struct tm tm;

    localtime_r(&now, &tm);

    snprintf(filepath, sizeof(filepath),
             "%s/auth_%04d%02d.log",
             dir,
             tm.tm_year + 1900,
             tm.tm_mon + 1);

    /* === open file (append, create if needed) === */
    int fd = open(filepath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        return;

    char line[512];

    char username_wrapped[128];

    wrap_log_str(username_wrapped, sizeof(username_wrapped), username ? username : "");

    int len = snprintf(line, sizeof(line),
        "[%s] %s %s %d %d\n",
        ts,
        username_wrapped,
        src_ip ? src_ip : "",
        src_port,
        attempts
    );

    if (len > 0 && len < sizeof(line)) {
        write(fd, line, len);
    }

    close(fd);
}

void log_connection_write(main_server_st *s, struct proc_st *proc, const char *action)
{
    struct list_head *head = s->vconfig;
    struct vhost_cfg_st *vhost = NULL;
    struct cfg_st *cfg = NULL;

    if (head && head->n.next != &head->n) {
        // first node
        struct list_node *node = head->n.next;
        vhost = container_of(node, struct vhost_cfg_st, list);
        cfg = vhost->perm_config.config;
    }

    if (!cfg)
        return;

    const char *dir = cfg->log_connection_dir;
    const char *tz  = cfg->log_timezone;

    if (!dir || dir[0] == '\0')
        return;

    /* timestamp */
    char ts[64];
    format_iso8601(ts, sizeof(ts), tz);

    // interface
    const char *iface = proc->tun_lease.name[0] ? proc->tun_lease.name : "";

    // username / group
    const char *username = proc->username[0] ? proc->username : "";
    const char *group    = proc->groupname[0] ? proc->groupname : "";

    // IPv4 / IPv6
    char ip4[INET_ADDRSTRLEN] = "";
    char ip6[INET6_ADDRSTRLEN] = "";

    if (proc->ipv4) {
        struct sockaddr *sa = (struct sockaddr *)&proc->ipv4->rip;
        if (sa->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)sa;
            inet_ntop(AF_INET, &sin->sin_addr, ip4, sizeof(ip4));
        }
    }

    if (proc->ipv6) {
        struct sockaddr *sa6 = (struct sockaddr *)&proc->ipv6->rip;
        if (sa6->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa6;
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip6, sizeof(ip6));
        }
    }

    // source IP / port
    char src_ip[INET6_ADDRSTRLEN] = "";
    char src_port[6] = "0";

    if (proc->remote_addr_len > 0) {
        struct sockaddr *sa = (struct sockaddr *)&proc->remote_addr;
        if (sa->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)sa;
            inet_ntop(AF_INET, &sin->sin_addr, src_ip, sizeof(src_ip));
            snprintf(src_port, sizeof(src_port), "%u", ntohs(sin->sin_port));
        } else if (sa->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
            inet_ntop(AF_INET6, &sin6->sin6_addr, src_ip, sizeof(src_ip));
            snprintf(src_port, sizeof(src_port), "%u", ntohs(sin6->sin6_port));
        }
    }

    /* === build filename: authfail_YYYYMM.log === */
    char filepath[512];
    time_t now = time(NULL);
    struct tm tm;

    localtime_r(&now, &tm);

    snprintf(filepath, sizeof(filepath),
             "%s/connection_%04d%02d.log",
             dir,
             tm.tm_year + 1900,
             tm.tm_mon + 1);

    /* === open file (append, create if needed) === */
    int fd = open(filepath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        return;

    char line[512];

    char username_wrapped[128];
    char group_wrapped[128];
    char src_port_wrapped[6];
    char iface_wrapped[32];
    char ip4_wrapped[18];
    char ip6_wrapped[42];

    wrap_log_str(username_wrapped, sizeof(username_wrapped), username);
    wrap_log_str(group_wrapped, sizeof(group_wrapped), group);
    wrap_log_str(src_port_wrapped, sizeof(src_port_wrapped), src_port);
    wrap_log_str(iface_wrapped, sizeof(iface_wrapped), iface);
    wrap_log_str(ip4_wrapped, sizeof(ip4_wrapped), ip4);
    wrap_log_str(ip6_wrapped, sizeof(ip6_wrapped), ip6);

    int len = snprintf(line, sizeof(line),
        "[%s] %s %s %s %s %s %s %s %s\n",
        ts,
        username_wrapped,
        group_wrapped,
        src_ip,
        src_port_wrapped,
        iface_wrapped,
        ip4_wrapped,
        ip6_wrapped,
        action
    );

    if (len > 0 && len < sizeof(line)) {
        write(fd, line, len);
    }

    close(fd);
}

/* Extract SNI from TLS ClientHello buffer */
const char *extract_sni_from_client_hello(uint8_t *buf, size_t len, char *out, size_t outlen)
{
    size_t i = 0;

    /* skip TLS record header (5 bytes) */
    if (len < 5)
        return "";

    i = 5;

    /* skip handshake header */
    if (i + 4 > len)
        return "";

    i += 4;

    /* skip version + random */
    if (i + 34 > len)
        return "";

    i += 34;

    /* session id */
    if (i + 1 > len)
        return "";
    uint8_t session_len = buf[i];
    i += 1 + session_len;

    /* cipher suites */
    if (i + 2 > len)
        return "";
    uint16_t cipher_len = (buf[i] << 8) | buf[i+1];
    i += 2 + cipher_len;

    /* compression */
    if (i + 1 > len)
        return "";
    uint8_t comp_len = buf[i];
    i += 1 + comp_len;

    /* extensions */
    if (i + 2 > len)
        return "";
    uint16_t ext_len = (buf[i] << 8) | buf[i+1];
    i += 2;

    size_t end = i + ext_len;

    while (i + 4 <= end && i + 4 <= len) {
        uint16_t type = (buf[i] << 8) | buf[i+1];
        uint16_t size = (buf[i+2] << 8) | buf[i+3];
        i += 4;

        if (type == 0x0000) { /* SNI */
            size_t j = i + 2; /* skip list length */

            if (j + 3 > len)
                return "";

            j++; /* name type */
            uint16_t name_len = (buf[j] << 8) | buf[j+1];
            j += 2;

            if (j + name_len > len || name_len >= outlen)
                return "";

            memcpy(out, &buf[j], name_len);
            out[name_len] = '\0';
            return out;
        }

        i += size;
    }

    return "";
}

/* Extract SNI (TLS) or Host header (HTTP) */
const char *extract_host_from_buffer(uint8_t *buf, size_t len, char *out, size_t outlen)
{
    /* --- Try TLS ClientHello --- */
    const char *sni = extract_sni_from_client_hello(buf, len, out, outlen);
    if (sni[0] != '\0')
        return sni;

    /* --- Fallback: try HTTP Host header --- */
    /* buf is ASCII, null-terminate safely */
    char tmp[1024] = {0};
    size_t copy_len = len < sizeof(tmp)-1 ? len : sizeof(tmp)-1;
    memcpy(tmp, buf, copy_len);
    tmp[copy_len] = '\0';

    /* simple line-based search */
    const char *line = tmp;
    while (*line) {
        /* find end of line */
        const char *eol = strstr(line, "\r\n");
        if (!eol)
            eol = line + strlen(line);

        if (strncasecmp(line, "Host:", 5) == 0) {
            /* skip "Host:" and whitespace */
            const char *p = line + 5;
            while (*p && isspace((unsigned char)*p)) p++;

            size_t host_len = eol - p;
            if (host_len > outlen - 6)   // 5 for "HTTP:" + 1 for '\0'
                host_len = outlen - 6;

            /* copy with prefix "HTTP:" */
            memcpy(out, "HTTP:", 5);
            memcpy(out + 5, p, host_len);
            out[5 + host_len] = '\0';
            return out;
        }

        /* move to next line */
        if (*eol == '\0') break;
        line = eol + 2; /* skip \r\n */
    }

    /* fallback: unknown host */
    out[0] = '\0';
    return out;
}
