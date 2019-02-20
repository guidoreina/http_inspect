#include <wdm.h>
#include "packet_pool.h"

typedef struct {
  packet_t** packets;
  unsigned max_packets;
  unsigned count;

  KSPIN_LOCK spin_lock;
} packet_pool_t;

static packet_pool_t pool;

BOOL InitPacketPool(unsigned max_packets, unsigned max_packet_size)
{
  unsigned i;

  if ((max_packets < MIN_PACKETS) || (max_packet_size < sizeof(packet_t))) {
    return FALSE;
  }

  if ((pool.packets = (packet_t**) ExAllocatePoolWithTag(
                                     NonPagedPool,
                                     max_packets * sizeof(packet_t*),
                                     PACKET_POOL_TAG
                                   )) == NULL) {
    return FALSE;
  }

  /* Create packets. */
  for (i = 0; i < max_packets; i++) {
    if ((pool.packets[i] = (packet_t*) ExAllocatePoolWithTag(
                                         NonPagedPool,
                                         max_packet_size,
                                         PACKET_POOL_TAG
                                       )) == NULL) {
      for (; i > 0; i--) {
        ExFreePoolWithTag(pool.packets[i - 1], PACKET_POOL_TAG);
      }

      ExFreePoolWithTag(pool.packets, PACKET_POOL_TAG);
      pool.packets = NULL;

      return FALSE;
    }
  }

  pool.max_packets = max_packets;
  pool.count = max_packets;

  KeInitializeSpinLock(&pool.spin_lock);

  return TRUE;
}

void FreePacketPool()
{
  unsigned i;

  if (pool.packets) {
    for (i = 0; i < pool.max_packets; i++) {
      if (pool.packets[i]) {
        ExFreePoolWithTag(pool.packets[i], PACKET_POOL_TAG);
      }
    }

    ExFreePoolWithTag(pool.packets, PACKET_POOL_TAG);
    pool.packets = NULL;
  }
}

void PushPacket(packet_t* packet)
{
  KLOCK_QUEUE_HANDLE lock_handle;

  /* Acquire spin lock. */
  KeAcquireInStackQueuedSpinLock(&pool.spin_lock, &lock_handle);

  /* If the pool is not full... */
  if (pool.count < pool.max_packets) {
    pool.packets[pool.count] = packet;
    pool.count++;
  }

  /* Release spin lock. */
  KeReleaseInStackQueuedSpinLock(&lock_handle);
}

packet_t* PopPacket()
{
  KLOCK_QUEUE_HANDLE lock_handle;
  packet_t* packet;

  /* Acquire spin lock. */
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&pool.spin_lock, &lock_handle);

  /* If the pool is not empty... */
  if (pool.count > 0) {
    pool.count--;

    packet = pool.packets[pool.count];
    pool.packets[pool.count] = NULL;
  } else {
    packet = NULL;
  }

  /* Release spin lock. */
  KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);

  return packet;
}
