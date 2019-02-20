#include <ntddk.h>

#pragma warning(push)
#pragma warning(disable:4201) /* Unnamed struct/union. */

#include <fwpsk.h>

#pragma warning(pop)

#include <ip2string.h>
#include "packet_processor.h"
#include "dnscache.h"
#include "logfile.h"

#define HOST_NAME_MAX_LEN 255
#define MAX_POINTERS 10
#define MAX_ANSWERS 32
#define MAX_CNAMES 8

typedef struct {
  char name[HOST_NAME_MAX_LEN + 1];
  UINT16 namelen;

  char alias[HOST_NAME_MAX_LEN + 1];
  UINT16 aliaslen;
} cname_t;

static void LogHttp(packet_t* packet,
                    const char* local,
                    const char* remote,
                    const char* str);

static void LogHttps(packet_t* packet,
                     const char* local,
                     const char* remote,
                     const char* str);

static void LogDns(packet_t* packet,
                   const char* local,
                   const char* remote);

static BOOL ParseHttpPacket(const UINT8* data,
                            SIZE_T len,
                            const UINT8** method,
                            SIZE_T* methodlen,
                            const UINT8** path,
                            SIZE_T* pathlen,
                            const UINT8** host,
                            SIZE_T* hostlen);

static BOOL ParseDns(LARGE_INTEGER* system_time, const UINT8* data, SIZE_T len);
static BOOL SkipDnsQuestions(const UINT8* end,
                             UINT16 qdcount,
                             const UINT8** ptr);

static BOOL SkipDnsName(const UINT8* end, const UINT8** ptr);
static BOOL ParseDnsName(const UINT8* data,
                         const UINT8* end,
                         const UINT8** ptr,
                         char* hostname,
                         UINT16* hostnamelen);

static const char* FindHostname(const cname_t* cnames,
                                unsigned ncnames,
                                const char* name,
                                UINT16 namelen,
                                UINT16* len);

void ProcessPacket(packet_t* packet)
{
  char local[128];
  char remote[128];
  ULONG localLen;
  ULONG remoteLen;
  char str[HOST_NAME_MAX_LEN + 1];

  localLen = ARRAYSIZE(local);
  remoteLen = ARRAYSIZE(remote);

  /* IPv4? */
  if (packet->ip_version == 4) {
    RtlIpv4AddressToStringExA((IN_ADDR*) packet->local_ip,
                              RtlUshortByteSwap(packet->local_port),
                              local,
                              &localLen);

    RtlIpv4AddressToStringExA((IN_ADDR*) packet->remote_ip,
                              RtlUshortByteSwap(packet->remote_port),
                              remote,
                              &remoteLen);

    if (!GetIPv4FromDnsCache(packet->remote_ip, str)) {
      *str = 0;
    }
  } else {
    RtlIpv6AddressToStringExA(
      (IN6_ADDR*) packet->local_ip,
      0,
      RtlUshortByteSwap(packet->local_port),
      local,
      &localLen
    );

    RtlIpv6AddressToStringExA(
      (IN6_ADDR*) packet->remote_ip,
      0,
      RtlUshortByteSwap(packet->remote_port),
      remote,
      &remoteLen
    );

    if (!GetIPv6FromDnsCache(packet->remote_ip, str)) {
      *str = 0;
    }
  }

  switch (packet->remote_port) {
    case 80: /* HTTP. */
      LogHttp(packet, local, remote, str);
      break;
    case 443: /* HTTPS. */
      LogHttps(packet, local, remote, str);
      break;
    case 53: /* DNS. */
      LogDns(packet, local, remote);
      break;
  }
}

void LogHttp(packet_t* packet,
             const char* local,
             const char* remote,
             const char* str)
{
  const UINT8* method;
  SIZE_T methodlen;
  const UINT8* path;
  SIZE_T pathlen;
  const UINT8* host;
  SIZE_T hostlen;

  /* If there is payload... */
  if (packet->payloadlen > 0) {
    if (ParseHttpPacket(packet->payload,
                        packet->payloadlen,
                        &method,
                        &methodlen,
                        &path,
                        &pathlen,
                        &host,
                        &hostlen)) {
      Log(&packet->timestamp,
          "[HTTP] [New connection] %s -> %s - %.*s http://%.*s%.*s\r\n",
          local,
          remote,
          methodlen,
          method,
          hostlen,
          host,
          pathlen,
          path);
    } else {
      if (*str) {
        Log(&packet->timestamp,
            "[HTTP] [New connection] %s -> %s (%s)\r\n",
            local,
            remote,
            str);
      } else {
        Log(&packet->timestamp,
            "[HTTP] [New connection] %s -> %s\r\n",
            local,
            remote);
      }
    }
  } else {
    if (*str) {
      Log(&packet->timestamp,
          "[HTTP] [Closed connection] %s -> %s (%s)\r\n",
          local,
          remote,
          str);
    } else {
      Log(&packet->timestamp,
          "[HTTP] [Closed connection] %s -> %s\r\n",
          local,
          remote);
    }
  }
}

void LogHttps(packet_t* packet,
              const char* local,
              const char* remote,
              const char* str)
{
  if (*str) {
    Log(&packet->timestamp,
        "[HTTPS] [%s] %s -> %s (%s)\r\n",
        (packet->payloadlen > 0) ? "New connection" : "Closed connection",
        local,
        remote,
        str);
  } else {
    Log(&packet->timestamp,
        "[HTTPS] [%s] %s -> %s\r\n",
        (packet->payloadlen > 0) ? "New connection" : "Closed connection",
        local,
        remote);
  }
}

void LogDns(packet_t* packet, const char* local, const char* remote)
{
  if (packet->payloadlen > 0) {
    Log(&packet->timestamp, "[DNS] %s -> %s\r\n", local, remote);
    ParseDns(&packet->timestamp, packet->payload, packet->payloadlen);
  } else {
    Log(&packet->timestamp, "[DNS] %s -> %s\r\n", local, remote);
  }
}

/* Disable warning:
 * Conditional expression is constant:
 * do {
 *   ...
 * } while (1);
 */
#pragma warning(disable:4127)

BOOL ParseHttpPacket(const UINT8* data,
                     SIZE_T len,
                     const UINT8** method,
                     SIZE_T* methodlen,
                     const UINT8** path,
                     SIZE_T* pathlen,
                     const UINT8** host,
                     SIZE_T* hostlen)
{
  const UINT8* end;
  const UINT8* ptr;

  end = data + len;
  ptr = data;

  /* Find method. */
  while (ptr < end) {
    if (*ptr > ' ') {
      *method = ptr++;
      break;
    } else {
      switch (*ptr) {
        case '\r':
        case '\n':
          ptr++;
          break;
        default:
          return FALSE;
      }
    }
  }

  /* Find end of method. */
  while ((ptr < end) && (*ptr > ' ')) {
    ptr++;
  }

  if (ptr == end) {
    return FALSE;
  }

  *methodlen = ptr - *method;

  /* Skip space after method. */
  ptr++;

  /* Find beginning of path. */
  while ((ptr < end) && ((*ptr == ' ') || (*ptr == '\t'))) {
    ptr++;
  }

  if (ptr == end) {
    return FALSE;
  }

  *path = ptr++;

  /* Find end of path. */
  while ((ptr < end) && (*ptr > ' ')) {
    ptr++;
  }

  if (ptr == end) {
    return FALSE;
  }

  *pathlen = ptr - *path;

  /* Skip space after path. */
  ptr++;

  if (ptr == end) {
    return FALSE;
  }

  /* Find host. */
  do {
    /* Find end of line. */
    if ((ptr = (const UINT8*) memchr(ptr, '\n', end - ptr)) == NULL) {
      return FALSE;
    }

    /* Skip end of line. */
    ptr++;

    if ((len = end - ptr) < 6) {
      return FALSE;
    }

    /* End of HTTP Header? */
    if ((*ptr == '\r') || (*ptr == '\n')) {
      return FALSE;
    }

    /* Host header? */
    if (memcmp(ptr, "Host:", 5) == 0) {
      ptr += 5;

      /* Skip spaces after header name. */
      while ((ptr < end) && ((*ptr == ' ') || (*ptr == '\t'))) {
        ptr++;
      }

      if (ptr == end) {
        return FALSE;
      }

      *host = ptr++;

      /* Search end of host. */
      while ((ptr < end) && (*ptr > ' ')) {
        ptr++;
      }

      if (ptr == end) {
        return FALSE;
      }

      *hostlen = ptr - *host;

      return TRUE;
    }
  } while (1);
}

BOOL ParseDns(LARGE_INTEGER* system_time, const UINT8* data, SIZE_T len)
{
  /* Format:
   *
   *   +---------------------+
   *   |        Header       |
   *   +---------------------+
   *   |       Question      | the question for the name server
   *   +---------------------+
   *   |        Answer       | RRs answering the question
   *   +---------------------+
   *   |      Authority      | RRs pointing toward an authority
   *   +---------------------+
   *   |      Additional     | RRs holding additional information
   *   +---------------------+
   *
   *
   *
   * The DNS header contains the following fields:
   *
   *                                   1  1  1  1  1  1
   *     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *   |                      ID                       |
   *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
   *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *   |                    QDCOUNT                    |
   *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *   |                    ANCOUNT                    |
   *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *   |                    NSCOUNT                    |
   *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *   |                    ARCOUNT                    |
   *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *
   */

  const UINT8* end;
  const UINT8* ptr;
  const UINT8* tmpptr;
  UINT16 qdcount;
  UINT16 ancount;
  UINT16 type, class, rdlength;
  cname_t cnames[MAX_CNAMES + 1];
  unsigned ncnames;
  cname_t* cname;
  char ip[128];
  const char* hostname;
  UINT16 hostnamelen;
  UINT16 i;

  /* If the DNS response is too small... */
  if (len < 12) {
    return FALSE;
  }

  /* If not a response... */
  if ((data[2] & 0x80) == 0) {
    return FALSE;
  }

  /* If not a standard query... */
  if (((data[2] >> 3) & 0x0f) != 0) {
    return FALSE;
  }

  /* If the message was truncated... */
  if (((data[2] >> 1) & 0x01) != 0) {
    return FALSE;
  }

  /* If the response code is not 0... */
  if ((data[3] & 0x0f) != 0) {
    return FALSE;
  }

  /* Get the number of questions. */
  qdcount = (data[4] << 8) | data[5];

  /* If no questions...*/
  if (qdcount == 0) {
    return FALSE;
  }

  /* Get the number of answers. */
  ancount = (data[6] << 8) | data[7];

  /* If no answers... */
  if (ancount == 0) {
    return FALSE;
  }

  /* Too many answers? */
  if (ancount > MAX_ANSWERS) {
    ancount = MAX_ANSWERS;
  }

  end = data + len;
  ptr = data + 12;

  /* Skip DNS questions. */
  if (!SkipDnsQuestions(end, qdcount, &ptr)) {
    return FALSE;
  }

  ncnames = 0;

  /* For each answer... */
  for (i = 0; i < ancount; i++) {
    cname = cnames + ncnames;

    /* Parse name. */
    if (!ParseDnsName(data, end, &ptr, cname->name, &cname->namelen)) {
      return FALSE;
    }

    if (ptr + 10 > end) {
      return FALSE;
    }

    /* Get type value. */
    type = (ptr[0] << 8) | ptr[1];

    /* Get class value. */
    class = (ptr[2] << 8) | ptr[3];

    /* Get RDLENGTH. */
    rdlength = (ptr[8] << 8) | ptr[9];

    if (ptr + 10 + rdlength > end) {
      return FALSE;
    }

    switch (type) {
      case 1: /* A record (IPv4). */
        if ((class != 1) || (rdlength != 4)) {
          return FALSE;
        }

        hostname = FindHostname(cnames,
                                ncnames,
                                cname->name,
                                cname->namelen,
                                &hostnamelen);

        AddIPv4ToDnsCache(ptr + 10, hostname, hostnamelen);

        Log(system_time,
            "Hostname: '%s' -> '%s', address: %u.%u.%u.%u.\r\n",
            cname->name,
            hostname,
            ptr[10],
            ptr[11],
            ptr[12],
            ptr[13]);

        break;
      case 5: /* CNAME. */
        if (class != 1) {
          return FALSE;
        }

        /* Parse name. */
        tmpptr = ptr + 10;
        if (!ParseDnsName(data, end, &tmpptr, cname->alias, &cname->aliaslen)) {
          return FALSE;
        }

        if (ncnames < MAX_CNAMES) {
          ncnames++;
        }

        Log(system_time,
            "Alias: '%s' -> hostname: '%s'.\r\n",
            cname->alias,
            cname->name);

        break;
      case 28: /* AAAA record (IPv6). */
        if ((class != 1) || (rdlength != 16)) {
          return FALSE;
        }

        hostname = FindHostname(cnames,
                                ncnames,
                                cname->name,
                                cname->namelen,
                                &hostnamelen);

        AddIPv6ToDnsCache(ptr + 10, hostname, hostnamelen);

        RtlIpv6AddressToStringA((IN6_ADDR*) ptr + 10, ip);
        Log(system_time,
            "Hostname: '%s' -> '%s', address: %s.\r\n",
            cname->name,
            hostname,
            ip);

        break;
    }

    ptr += (10 + rdlength);
  }

  return TRUE;
}

BOOL SkipDnsQuestions(const UINT8* end, UINT16 qdcount, const UINT8** ptr)
{
  const UINT8* p;
  UINT16 i;

  p = *ptr;

  /* For each question... */
  for (i = 0; i < qdcount; i++) {
    /* Skip name. */
    if (!SkipDnsName(end, &p)) {
      return FALSE;
    }

    /* Skip QTYPE and QCLASS. */
    if ((p += 4) > end) {
      return FALSE;
    }
  }

  *ptr = p;

  return TRUE;
}

BOOL SkipDnsName(const UINT8* end, const UINT8** ptr)
{
  const UINT8* p;
  UINT8 l;

  if ((p = *ptr) == end) {
    return FALSE;
  }

  while ((l = *p) != 0) {
    switch (l & 0xc0) {
      case 0: /* Not a pointer. */
        if ((p += (1 + l)) >= end) {
          return FALSE;
        }

        break;
      case 0xc0: /* Pointer. */
        if ((p += 2) > end) {
          return FALSE;
        }

        *ptr = p;
        return TRUE;
      default:
        return FALSE;
    }
  }

  /* Skip '\0'. */
  *ptr = p + 1;

  return TRUE;
}

BOOL ParseDnsName(const UINT8* data,
                  const UINT8* end,
                  const UINT8** ptr,
                  char* hostname,
                  UINT16* hostnamelen)
{
  const UINT8* p;
  unsigned npointers;
  UINT16 len;
  UINT8 l;

  if ((p = *ptr) == end) {
    return FALSE;
  }

  npointers = 0;
  len = 0;

  while ((l = *p) != 0) {
    switch (l & 0xc0) {
      case 0: /* Not a pointer. */
        if ((p + 1 + l >= end) || (len + 1 + l > HOST_NAME_MAX_LEN)) {
          return FALSE;
        }

        if (len > 0) {
          hostname[len++] = '.';
        }

        memcpy(hostname + len, p + 1, l);
        len += l;

        p += (1 + l);
        break;
      case 0xc0: /* Pointer. */
        if (p + 2 > end) {
          return FALSE;
        }

        /* Too many pointers? */
        if (++npointers > MAX_POINTERS) {
          return FALSE;
        }

        /* First pointer? */
        if (npointers == 1) {
          *ptr = p + 2;
        }

        if ((p = data + (((l & 0x3f) << 8) | p[1])) >= end) {
          return FALSE;
        }

        break;
      default:
        return FALSE;
    }
  }

  if (len == 0) {
    return FALSE;
  }

  hostname[len] = 0;

  if (npointers == 0) {
    /* Skip '\0'. */
    *ptr = p + 1;
  }

  *hostnamelen = len;

  return TRUE;
}

const char* FindHostname(const cname_t* cnames,
                         unsigned ncnames,
                         const char* name,
                         UINT16 namelen,
                         UINT16* len)
{
  const cname_t* cname;
  unsigned i;

  for (i = ncnames; i > 0; i--) {
    cname = cnames + (i - 1);

    if ((cname->aliaslen == namelen) &&
        (memcmp(cname->alias, name, namelen) == 0)) {
      name = cname->name;
      namelen = cname->namelen;
    }
  }

  *len = namelen;

  return name;
}
