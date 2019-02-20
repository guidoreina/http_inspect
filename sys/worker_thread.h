#ifndef WORKER_THREAD_H
#define WORKER_THREAD_H

#pragma warning(push)
#pragma warning(disable:4201) /* Unnamed struct/union. */

#include <fwpsk.h>

#pragma warning(pop)

#include "packet_pool.h"

BOOL InitWorkerThread(unsigned max_packets);
void FreeWorkerThread();

NTSTATUS StartWorkerThread();
void StopWorkerThread();

BOOL GivePacketToWorkerThread(packet_t* packet);

#endif /* WORKER_THREAD_H */
