#include "worker_thread.h"
#include "packet_processor.h"
#include "logfile.h"

#define FLUSH_LOGS_EVERY_MS 1000

typedef struct {
  packet_t** packets;
  unsigned max_packets;
  unsigned count;

  void* thread;
  BOOL running;

  KSPIN_LOCK spin_lock;
  KSEMAPHORE semaphore;
} worker_thread_t;

static worker_thread_t worker;

static void ThreadProc(void* context);

BOOL InitWorkerThread(unsigned max_packets)
{
  if (max_packets < MIN_PACKETS) {
    return FALSE;
  }

  if ((worker.packets = (packet_t**) ExAllocatePoolWithTag(
                                       NonPagedPool,
                                       max_packets * sizeof(packet_t*),
                                       PACKET_POOL_TAG
                                     )) == NULL) {
    return FALSE;
  }

  worker.max_packets = max_packets;
  worker.count = 0;

  worker.thread = NULL;
  worker.running = FALSE;

  KeInitializeSpinLock(&worker.spin_lock);
  KeInitializeSemaphore(&worker.semaphore, 0, max_packets);

  return TRUE;
}

void FreeWorkerThread()
{
  unsigned i;

  if (worker.packets) {
    for (i = 0; i < worker.count; i++) {
      ExFreePoolWithTag(worker.packets[i], PACKET_POOL_TAG);
    }

    ExFreePoolWithTag(worker.packets, PACKET_POOL_TAG);
    worker.packets = NULL;
  }
}

NTSTATUS StartWorkerThread()
{
  HANDLE thread;
  NTSTATUS status;

  worker.running = TRUE;

  status = PsCreateSystemThread(&thread,
                                THREAD_ALL_ACCESS,
                                NULL,
                                NULL,
                                NULL,
                                ThreadProc,
                                NULL);

  if (!NT_SUCCESS(status)) {
    worker.running = FALSE;
    return status;
  }

  ObReferenceObjectByHandle(thread, 0, NULL, KernelMode, &worker.thread, NULL);

  ZwClose(thread);

  return STATUS_SUCCESS;
}

void StopWorkerThread()
{
  if (worker.running) {
    worker.running = FALSE;

    KeReleaseSemaphore(&worker.semaphore, IO_NO_INCREMENT, 1, FALSE);

    KeWaitForSingleObject(worker.thread, Executive, KernelMode, FALSE, NULL);
    worker.thread = NULL;
  }
}

BOOL GivePacketToWorkerThread(packet_t* packet)
{
  KLOCK_QUEUE_HANDLE lock_handle;

  /* Acquire spin lock. */
  KeAcquireInStackQueuedSpinLockAtDpcLevel(&worker.spin_lock, &lock_handle);

  if (worker.count < worker.max_packets) {
    worker.packets[worker.count] = packet;
    worker.count++;

    /* Release spin lock. */
    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);

    KeReleaseSemaphore(&worker.semaphore, IO_NO_INCREMENT, 1, FALSE);

    return TRUE;
  } else {
    /* Release spin lock. */
    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);

    return FALSE;
  }
}

/* Disable warning:
 * Conditional expression is constant:
 * do {
 *   ...
 * } while (1);
 */
#pragma warning(disable:4127)

void ThreadProc(void* context)
{
  KLOCK_QUEUE_HANDLE lock_handle;
  LARGE_INTEGER timeout;
  packet_t* packet;

  UNREFERENCED_PARAMETER(context);

  timeout = RtlConvertLongToLargeInteger(-10000 * FLUSH_LOGS_EVERY_MS);

  do {
    /* Wait for packet. */
    switch (KeWaitForSingleObject(&worker.semaphore,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  &timeout)) {
      case STATUS_SUCCESS:
        if (!worker.running) {
          return;
        }

        /* Acquire spin lock. */
        KeAcquireInStackQueuedSpinLock(&worker.spin_lock, &lock_handle);

        if (worker.count > 0) {
          worker.count--;
          packet = worker.packets[worker.count];

          /* Release spin lock. */
          KeReleaseInStackQueuedSpinLock(&lock_handle);

          /* Process packet. */
          ProcessPacket(packet);

          /* Return packet to the packet pool. */
          PushPacket(packet);
        } else {
          /* Release spin lock. */
          KeReleaseInStackQueuedSpinLock(&lock_handle);
        }

        break;
      case STATUS_TIMEOUT:
        if (!worker.running) {
          return;
        }

        FlushLog();
        break;
    }
  } while (TRUE);
}
