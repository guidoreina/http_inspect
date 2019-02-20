#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "dnscache.h"

#define MAX_BINS 32

#define HOST_NAME_MIN_LEN 8
#define HOST_NAME_MAX_LEN 255

#define TAG '1gaT'

/* http://burtleburtle.net/bob/hash/doobs.html */
#define mix(a, b, c)                      \
        {                                 \
          a -= b; a -= c; a ^= (c >> 13); \
          b -= c; b -= a; b ^= (a << 8);  \
          c -= a; c -= b; c ^= (b >> 13); \
          a -= b; a -= c; a ^= (c >> 12); \
          b -= c; b -= a; b ^= (a << 16); \
          c -= a; c -= b; c ^= (b >> 5);  \
          a -= b; a -= c; a ^= (c >> 3);  \
          b -= c; b -= a; b ^= (a << 10); \
          c -= a; c -= b; c ^= (b >> 15); \
        }

typedef struct page_t {
  struct page_t* next;
  int free;

  char data[1];
} page_t;

typedef struct {
  page_t* page;
  unsigned off;
  UINT16 len;
} hostname_t;

typedef struct cache_header_t {
  struct cache_header_t* prev;
  struct cache_header_t* next;
} cache_header_t;

typedef struct cache_time_t {
  void* unused1;
  void* unused2;

  struct cache_time_t* older;
  struct cache_time_t* newer;
} cache_time_t;

typedef struct cache_entry_t {
  struct cache_entry_t* prev;
  struct cache_entry_t* next;

  struct cache_entry_t* newer;
  struct cache_entry_t* older;

  hostname_t hostname;
  UINT8 ip[1];
} cache_entry_t;

typedef struct {
  cache_header_t* buckets;
  cache_entry_t* entries;
  cache_entry_t* free;
  cache_time_t time;
  unsigned nbuckets;

  page_t* bins[MAX_BINS];

  UINT32 (*hash)(const UINT8* ip, unsigned max);
} dns_cache_t;

static dns_cache_t ipv4_cache;
static dns_cache_t ipv6_cache;

static UINT16 bins_max_len[MAX_BINS];
static UINT8 bucket_indices[HOST_NAME_MAX_LEN + 1];

static BOOL InitCache(dns_cache_t* ip_cache,
                      unsigned nbuckets,
                      unsigned max,
                      SIZE_T ip_size);

static void FreeCache(dns_cache_t* ip_cache);

static BOOL AddIPToDnsCache(dns_cache_t* ip_cache,
                            const UINT8* ip,
                            SIZE_T ip_size,
                            const char* hostname,
                            UINT16 hostnamelen);

static const char* GetIPFromDnsCache(dns_cache_t* ip_cache,
                                     const UINT8* ip,
                                     SIZE_T ip_size,
                                     char* hostname);

static void TouchCacheEntry(dns_cache_t* ip_cache,
                            cache_header_t* header,
                            cache_entry_t* entry);

__inline static void UnlinkCacheEntry(cache_entry_t* entry)
{
  entry->prev->next = entry->next;
  entry->next->prev = entry->prev;
}

static void MakeCacheEntryNewest(dns_cache_t* ip_cache, cache_entry_t* entry);

static BOOL SaveHost(dns_cache_t* ip_cache,
                     unsigned bin,
                     const char* hostname,
                     UINT16 hostnamelen,
                     page_t** page,
                     unsigned* off);

static void RemoveFromPage(hostname_t* host);
static void FreeBin(page_t* page);
static UINT32 HashIPv4(const UINT8* ip, unsigned nbuckets);
static UINT32 HashIPv6(const UINT8* ip, unsigned nbuckets);

__inline static unsigned BucketIndex(UINT16 hostnamelen)
{
  return bucket_indices[hostnamelen];
}

__inline static void* MemAlloc(SIZE_T size)
{
  return ExAllocatePoolWithTag(NonPagedPool, size, TAG);
}

__inline static void MemFree(void* ptr)
{
  ExFreePoolWithTag(ptr, TAG);
}

BOOL InitDnsCache(unsigned nbuckets, unsigned max)
{
  unsigned n;
  UINT16 step;
  unsigned i;
  UINT8 idx;

  if (max == 0) {
    return FALSE;
  }

  /* Initialize IPv4 cache. */
  if (!InitCache(&ipv4_cache, nbuckets, max, 4)) {
    return FALSE;
  }

  /* Initialize IPv6 cache. */
  if (!InitCache(&ipv6_cache, nbuckets, max, 16)) {
    FreeCache(&ipv4_cache);
    return FALSE;
  }

  n = HOST_NAME_MAX_LEN - HOST_NAME_MIN_LEN + 1;
  step = (UINT16) (n / (MAX_BINS - 1));

  if ((n % (MAX_BINS - 1)) != 0) {
    step++;
  }

  bins_max_len[0] = HOST_NAME_MIN_LEN;

  for (i = 1; i < MAX_BINS; i++) {
    bins_max_len[i] = bins_max_len[i - 1] + step;
  }

  for (i = 0; i <= HOST_NAME_MIN_LEN; i++) {
    bucket_indices[i] = 0;
  }

  idx = 1;

  for (; i <= HOST_NAME_MAX_LEN; i++) {
    bucket_indices[i] = idx;

    if (((i - HOST_NAME_MIN_LEN) % step) == 0) {
      idx++;
    }
  }

  ipv4_cache.hash = HashIPv4;
  ipv6_cache.hash = HashIPv6;

  return TRUE;
}

void FreeDnsCache()
{
  FreeCache(&ipv4_cache);
  FreeCache(&ipv6_cache);
}

BOOL AddIPv4ToDnsCache(const UINT8* ipv4,
                       const char* hostname,
                       UINT16 hostnamelen)
{
  return AddIPToDnsCache(&ipv4_cache, ipv4, 4, hostname, hostnamelen);
}

BOOL AddIPv6ToDnsCache(const UINT8* ipv6,
                       const char* hostname,
                       UINT16 hostnamelen)
{
  return AddIPToDnsCache(&ipv6_cache, ipv6, 16, hostname, hostnamelen);
}

const char* GetIPv4FromDnsCache(const UINT8* ipv4, char* hostname)
{
  return GetIPFromDnsCache(&ipv4_cache, ipv4, 4, hostname);
}

const char* GetIPv6FromDnsCache(const UINT8* ipv6, char* hostname)
{
  return GetIPFromDnsCache(&ipv6_cache, ipv6, 16, hostname);
}

BOOL InitCache(dns_cache_t* ip_cache,
               unsigned nbuckets,
               unsigned max,
               SIZE_T ip_size)
{
  cache_entry_t* entry;
  cache_entry_t* next;
  size_t sizeof_cache_entry;
  unsigned i;

  /* Allocate memory for the buckets. */
  if ((ip_cache->buckets = (cache_header_t*)
                           MemAlloc(nbuckets * sizeof(cache_header_t)))
      == NULL) {
    return FALSE;
  }

  /* Calculate size of the cache entry. */
  sizeof_cache_entry = offsetof(cache_entry_t, ip) + ip_size;

  /* Allocate memory for all the entries. */
  if ((ip_cache->entries = (cache_entry_t*) MemAlloc(max * sizeof_cache_entry))
      == NULL) {
    MemFree(ip_cache->buckets);
    return FALSE;
  }

  for (i = 0; i < nbuckets; i++) {
    ip_cache->buckets[i].prev = &ip_cache->buckets[i];
    ip_cache->buckets[i].next = &ip_cache->buckets[i];
  }

  entry = ip_cache->entries;

  for (i = 0; i + 1 < max; i++) {
    next = (cache_entry_t*) ((UINT8*) entry + sizeof_cache_entry);

    entry->next = next;
    entry = next;
  }

  entry->next = NULL;

  ip_cache->free = ip_cache->entries;

  ip_cache->time.older = &ip_cache->time;
  ip_cache->time.newer = &ip_cache->time;

  ip_cache->nbuckets = nbuckets;

  memset(ip_cache->bins, 0, sizeof(ip_cache->bins));

  return TRUE;
}

void FreeCache(dns_cache_t* ip_cache)
{
  unsigned i;

  if (ip_cache->buckets) {
    MemFree(ip_cache->buckets);
    ip_cache->buckets = NULL;
  }

  if (ip_cache->entries) {
    MemFree(ip_cache->entries);
    ip_cache->entries = NULL;
  }

  for (i = 0; i < MAX_BINS; i++) {
    if (ip_cache->bins[i]) {
      FreeBin(ip_cache->bins[i]);
      ip_cache->bins[i] = NULL;
    }
  }
}

BOOL AddIPToDnsCache(dns_cache_t* ip_cache,
                     const UINT8* ip,
                     SIZE_T ip_size,
                     const char* hostname,
                     UINT16 hostnamelen)
{
  cache_header_t* header;
  cache_entry_t* entry;
  hostname_t* host;
  page_t* page;
  char* s;
  unsigned off;
  unsigned oldbin;
  unsigned newbin;

  /* If the hostname is too long... */
  if (hostnamelen > HOST_NAME_MAX_LEN) {
    return FALSE;
  }

  header = &ip_cache->buckets[ip_cache->hash(ip, ip_cache->nbuckets)];
  entry = (cache_entry_t*) header->next;

  while (entry != (cache_entry_t*) header) {
    /* Same IP address? */
    if (memcmp(ip, entry->ip, ip_size) == 0) {
      host = &entry->hostname;

      /* If the hostnames have the same length... */
      if (hostnamelen == host->len) {
        /* Same hostname? */
        s = host->page->data + host->off;
        if (memcmp(hostname, s, hostnamelen) == 0) {
          /* Already inserted. */
          TouchCacheEntry(ip_cache, header, entry);

          return TRUE;
        }

        /* Overwrite hostname. */
        memcpy(s, hostname, hostnamelen);

        TouchCacheEntry(ip_cache, header, entry);

        return TRUE;
      }

      oldbin = BucketIndex(host->len);
      newbin = BucketIndex(hostnamelen);

      /* If the hostnames are in the same bin... */
      if (oldbin == newbin) {
        s = host->page->data + host->off;
        memcpy(s, hostname, hostnamelen);
        host->len = hostnamelen;

        TouchCacheEntry(ip_cache, header, entry);

        return TRUE;
      }

      if (!SaveHost(ip_cache, newbin, hostname, hostnamelen, &page, &off)) {
        return FALSE;
      }

      RemoveFromPage(host);

      host->page = page;
      host->off = off;
      host->len = hostnamelen;

      TouchCacheEntry(ip_cache, header, entry);

      return TRUE;
    }

    entry = entry->next;
  }

  /* Save host in the corresponding bin. */
  if (!SaveHost(ip_cache,
                BucketIndex(hostnamelen),
                hostname,
                hostnamelen,
                &page,
                &off)) {
    return FALSE;
  }

  /* If there is a free entry... */
  if ((entry = ip_cache->free) != NULL) {
    ip_cache->free = entry->next;

    entry->newer = (cache_entry_t*) &ip_cache->time;
    entry->older = (cache_entry_t*) ip_cache->time.newer;

    entry->older->newer = entry;
    ip_cache->time.newer = (cache_time_t*) entry;
  } else {
    /* Free the oldest entry. */
    entry = (cache_entry_t*) ip_cache->time.older;

    UnlinkCacheEntry(entry);
    MakeCacheEntryNewest(ip_cache, entry);

    RemoveFromPage(&entry->hostname);
  }

  entry->hostname.page = page;
  entry->hostname.off = off;
  entry->hostname.len = hostnamelen;

  memcpy(entry->ip, ip, ip_size);

  entry->prev = (cache_entry_t*) header;
  entry->next = (cache_entry_t*) header->next;

  entry->next->prev = entry;
  header->next = (cache_header_t*) entry;

  return TRUE;
}

const char* GetIPFromDnsCache(dns_cache_t* ip_cache,
                              const UINT8* ip,
                              SIZE_T ip_size,
                              char* hostname)
{
  cache_header_t* header;
  cache_entry_t* entry;
  const hostname_t* host;

  header = &ip_cache->buckets[ip_cache->hash(ip, ip_cache->nbuckets)];
  entry = (cache_entry_t*) header->next;

  while (entry != (cache_entry_t*) header) {
    /* Same IP address? */
    if (memcmp(ip, entry->ip, ip_size) == 0) {
      host = &entry->hostname;

      memcpy(hostname, host->page->data + host->off, host->len);
      hostname[host->len] = 0;

      TouchCacheEntry(ip_cache, header, entry);

      return hostname;
    }

    entry = entry->next;
  }

  return NULL;
}

void TouchCacheEntry(dns_cache_t* ip_cache,
                     cache_header_t* header,
                     cache_entry_t* entry)
{
  /* If not the first entry... */
  if (entry != (cache_entry_t*) header->next) {
    UnlinkCacheEntry(entry);

    /* Move entry to the first position. */
    entry->prev = (cache_entry_t*) header;
    entry->next = (cache_entry_t*) header->next;

    entry->next->prev = entry;
    header->next = (cache_header_t*) entry;
  }

  /* Make entry the newest. */
  MakeCacheEntryNewest(ip_cache, entry);
}

void MakeCacheEntryNewest(dns_cache_t* ip_cache, cache_entry_t* entry)
{
  /* If not the newest entry... */
  if (entry != (cache_entry_t*) ip_cache->time.newer) {
    /* Unlink entry. */
    entry->older->newer = entry->newer;
    entry->newer->older = entry->older;

    /* Make entry the newest. */
    entry->newer = (cache_entry_t*) &ip_cache->time;
    entry->older = (cache_entry_t*) ip_cache->time.newer;

    entry->older->newer = entry;
    ip_cache->time.newer = (cache_time_t*) entry;
  }
}

BOOL SaveHost(dns_cache_t* ip_cache,
              unsigned bin,
              const char* hostname,
              UINT16 hostnamelen,
              page_t** page,
              unsigned* off)
{
  page_t* pg;
  char* data;
  char* s;
  unsigned offset;
  UINT16 maxbin;
  unsigned count;
  unsigned i;

  pg = ip_cache->bins[bin];

  while (pg) {
    /* If there is space in the page... */
    if (pg->free != -1) {
      s = pg->data + pg->free;

      *page = pg;
      *off = pg->free;

      pg->free = *((int*) s);

      memcpy(s, hostname, hostnamelen);

      return TRUE;
    }

    pg = pg->next;
  }

  /* Create page. */
  if ((pg = MemAlloc(PAGE_SIZE)) == NULL) {
    return FALSE;
  }

  maxbin = bins_max_len[bin];

  /* Number of hostnames that fit in the page. */
  count = (PAGE_SIZE - offsetof(page_t, data)) / maxbin;

  data = pg->data;
  offset = maxbin;

  for (i = 1; i + 1 < count; i++) {
    s = data + offset;

    offset += maxbin;

    *((int*) s) = offset;
  }

  *((int*) (data + offset)) = -1;

  pg->free = maxbin;
  pg->next = ip_cache->bins[bin];

  ip_cache->bins[bin] = pg;

  /* Save hostname. */
  memcpy(data, hostname, hostnamelen);

  *page = pg;
  *off = 0;

  return TRUE;
}

void RemoveFromPage(hostname_t* host)
{
  int* next;

  next = (int*) (host->page->data + host->off);
  *next = host->page->free;
  host->page->free = host->off;
}

void FreeBin(page_t* page)
{
  page_t* next;

  do {
    next = page->next;
    MemFree(page);
    page = next;
  } while (page);
}

UINT32 HashIPv4(const UINT8* ip, unsigned nbuckets)
{
  UINT32 a;

  a = *((UINT32*) ip);

  /* http://burtleburtle.net/bob/hash/integer.html */
  a = a ^ (a >> 4);
  a = (a ^ 0xdeadbeef) + (a << 5);

  return ((a ^ (a >> 11)) % nbuckets);
}

UINT32 HashIPv6(const UINT8* ip, unsigned nbuckets)
{
  /* http://burtleburtle.net/bob/hash/doobs.html */

  static UINT32 initval = 0xdeaddead;
  UINT32 a, b, c;

  /* Set up the internal state. */
  a = b = 0x9e3779b9; /* The golden ratio; an arbitrary value. */
  c = initval; /* The previous hash value. */

  /*--------------------------------------- Handle most of the key. */
  a += (ip[0] +
        ((UINT32) ip[1] << 8) +
        ((UINT32) ip[2] << 16) +
        ((UINT32) ip[3] << 24));

  b += (ip[4] +
        ((UINT32) ip[5] << 8) +
        ((UINT32) ip[6] << 16) +
        ((UINT32) ip[7] << 24));

  c += (ip[8] +
        ((UINT32) ip[9] << 8) +
        ((UINT32) ip[10] << 16) +
        ((UINT32) ip[11] << 24));

  mix(a, b, c);

  /*-------------------------------------- Handle the last 4 bytes. */
  a += (((UINT32) ip[15] << 24) +
        ((UINT32) ip[14] << 16) +
        ((UINT32) ip[13] << 8) +
        ip[12]);

  c += 16;
  mix(a, b, c);

  initval = c; /* Save the last hash value. */

  /*-------------------------------------------- Report the result. */
  return (c % nbuckets);
}
