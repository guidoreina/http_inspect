#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#pragma warning(push)
#pragma warning(disable:4201) /* Unnamed struct/union. */

#include <fwpsk.h>

#pragma warning(pop)

BOOL InitDnsCache(unsigned nbuckets, unsigned max);
void FreeDnsCache();

BOOL AddIPv4ToDnsCache(const UINT8* ipv4,
                       const char* hostname,
                       UINT16 hostnamelen);

BOOL AddIPv6ToDnsCache(const UINT8* ipv6,
                       const char* hostname,
                       UINT16 hostnamelen);

const char* GetIPv4FromDnsCache(const UINT8* ipv4, char* hostname);
const char* GetIPv6FromDnsCache(const UINT8* ipv6, char* hostname);

#endif /* DNS_CACHE_H */
