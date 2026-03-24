#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <gnutls/gnutls.h>

#include "vpn.h"
#include "worker.h"
#include "tlslib.h"
#include "common.h"

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

void log_access_write(worker_st *ws, const char *ts, const char *src_ip, const char *sni, const char *ua, const char *path, int status)
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

    int len = snprintf(line, sizeof(line),
        "[%s] %s %s \"%s\" \"%s\" %03d\n",
        ts,
        src_ip ? src_ip : "",
        sni ? sni : "",
        ua ? ua : "",
        path ? path : "",
        status);

    if (len > 0) {
        write(fd, line, len);
    }

    close(fd);
}
