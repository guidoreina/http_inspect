#ifndef PACKET_POOL_H
#define PACKET_POOL_H

#pragma warning(push)
#pragma warning(disable:4201) /* Unnamed struct/union. */

#include <fwpsk.h>

#pragma warning(pop)

#define MIN_PACKETS 32
#define PACKET_POOL_TAG '1gaT'

typedef struct {
  UINT8 ip_version;

  UINT8 local_ip[16];
  UINT8 remote_ip[16];

  UINT16 local_port;
  UINT16 remote_port;

  LARGE_INTEGER timestamp;

  UINT16 payloadlen;
  UINT8 payload[1];
} packet_t;

BOOL InitPacketPool(unsigned max_packets, unsigned max_packet_size);
void FreePacketPool();

void PushPacket(packet_t* packet);
packet_t* PopPacket();

#endif /* PACKET_POOL_H */
