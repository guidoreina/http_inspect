#include <stddef.h>
#include <ndis.h>

#pragma warning(push)
#pragma warning(disable:4201) /* Unnamed struct/union. */

#include <fwpsk.h>

#pragma warning(pop)

#include "inspect.h"
#include "worker_thread.h"
#include "packet_pool.h"
#include "utils.h"

#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - offsetof(packet_t, payload))


/*******************************************************************************
 *******************************************************************************
 **                                                                           **
 ** FillPacket.                                                               **
 **                                                                           **
 *******************************************************************************
 *******************************************************************************/

static BOOL FillPacket(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
                       _Inout_opt_ void* layerData,
                       _Out_ packet_t* packet)
{
  const FWPS_INCOMING_VALUE* values;
  UINT localAddrIndex;
  UINT remoteAddrIndex;
  UINT localPortIndex;
  UINT remotePortIndex;
  UINT32 addr;
  NET_BUFFER* nb;
  const UINT8* payload;

  if (!GetNetwork4TupleIndexesForLayer(inFixedValues->layerId,
                                       &localAddrIndex,
                                       &remoteAddrIndex,
                                       &localPortIndex,
                                       &remotePortIndex)) {
    return FALSE;
  }

  values = inFixedValues->incomingValue;

  packet->local_port = values[localPortIndex].value.uint16;
  packet->remote_port = values[remotePortIndex].value.uint16;

  /* IPv4? */
  if (GetAddressFamilyForLayer(inFixedValues->layerId) == AF_INET) {
    packet->ip_version = 4;

    addr = RtlUlongByteSwap(values[localAddrIndex].value.uint32);
    memcpy(packet->local_ip, &addr, 4);

    addr = RtlUlongByteSwap(values[remoteAddrIndex].value.uint32);
    memcpy(packet->remote_ip, &addr, 4);
  } else {
    packet->ip_version = 6;

    memcpy(packet->local_ip,
           values[localAddrIndex].value.byteArray16->byteArray16,
           16);

    memcpy(packet->remote_ip,
           values[remoteAddrIndex].value.byteArray16->byteArray16,
           16);
  }

  if (layerData) {
    switch (packet->remote_port) {
      case 80: /* HTTP. */
        nb = NET_BUFFER_LIST_FIRST_NB(
               ((FWPS_STREAM_CALLOUT_IO_PACKET0*) layerData)->streamData
                                                            ->netBufferListChain
             );

        /* Get pointer to payload. */
        if ((payload = NdisGetDataBuffer(nb,
                                         nb->DataLength,
                                         NULL,
                                         2,
                                         0)) == NULL) {
          return FALSE;
        }

        packet->payloadlen = (UINT16) ((nb->DataLength < MAX_PAYLOAD_SIZE) ?
                                        nb->DataLength :
                                        MAX_PAYLOAD_SIZE);

        memcpy(packet->payload, payload, packet->payloadlen);

        break;
      case 443: /* HTTPS. */
        if (((FWPS_STREAM_CALLOUT_IO_PACKET0*) layerData)->streamData) {
          nb = NET_BUFFER_LIST_FIRST_NB(
                 ((FWPS_STREAM_CALLOUT_IO_PACKET0*) layerData)
                   ->streamData->netBufferListChain
               );

          /* Payload won't be processed. */
          packet->payloadlen = (UINT16) nb->DataLength;
        } else {
          return FALSE;
        }

        break;
      case 53: /* DNS. */
        nb = NET_BUFFER_LIST_FIRST_NB((NET_BUFFER_LIST*) layerData);

        /* Get pointer to payload. */
        if ((payload = NdisGetDataBuffer(nb,
                                         nb->DataLength,
                                         NULL,
                                         2,
                                         0)) == NULL) {
          return FALSE;
        }

        packet->payloadlen = (UINT16) ((nb->DataLength < MAX_PAYLOAD_SIZE) ?
                                        nb->DataLength :
                                        MAX_PAYLOAD_SIZE);

        memcpy(packet->payload, payload, packet->payloadlen);

        break;
    }
  } else {
    packet->payloadlen = 0;
  }

  KeQuerySystemTime(&packet->timestamp);

  return TRUE;
}


/*******************************************************************************
 *******************************************************************************
 **                                                                           **
 ** Stream.                                                                   **
 **                                                                           **
 *******************************************************************************
 *******************************************************************************/

NTSTATUS StreamNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                      _In_ const GUID* filterKey,
                      _Inout_ const FWPS_FILTER* filter)
{
  UNREFERENCED_PARAMETER(notifyType);
  UNREFERENCED_PARAMETER(filterKey);
  UNREFERENCED_PARAMETER(filter);

#if DEBUG
  DbgPrint("StreamNotify()");
#endif

  return STATUS_SUCCESS;
}

void StreamClassify(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
                    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
                    _Inout_opt_ void* layerData,
#if(NTDDI_VERSION >= NTDDI_WIN7)
                    _In_opt_ const void* classifyContext,
#endif
                    _In_ const FWPS_FILTER* filter,
                    _In_ UINT64 flowContext,
                    _Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
  packet_t* packet;

  UNREFERENCED_PARAMETER(inMetaValues);

#if(NTDDI_VERSION >= NTDDI_WIN7)
  UNREFERENCED_PARAMETER(classifyContext);
#endif

  UNREFERENCED_PARAMETER(filter);
  UNREFERENCED_PARAMETER(flowContext);

#if DEBUG
  DbgPrint("StreamClassify()");
#endif

  /* Get packet from the packet pool. */
  if ((packet = PopPacket()) != NULL) {
    if (FillPacket(inFixedValues, layerData, packet)) {
      if (!GivePacketToWorkerThread(packet)) {
        /* Return packet to packet pool. */
        PushPacket(packet);
      }
    } else {
      /* Return packet to packet pool. */
      PushPacket(packet);
    }
  }

  FWPS_STREAM_CALLOUT_IO_PACKET0* pkt =
                                  (FWPS_STREAM_CALLOUT_IO_PACKET0*) layerData;

  /* If we want to get all the data, use:
   * pkt-> streamAction = FWP_ACTION_CONTINUE;
   */
  pkt->streamAction = FWPS_STREAM_ACTION_ALLOW_CONNECTION;
  pkt->countBytesEnforced = 0;
  pkt->countBytesRequired = 0;

  classifyOut->actionType = FWP_ACTION_CONTINUE;
}


/*******************************************************************************
 *******************************************************************************
 **                                                                           **
 ** Datagram.                                                                 **
 **                                                                           **
 *******************************************************************************
 *******************************************************************************/

NTSTATUS DatagramNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                        _In_ const GUID* filterKey,
                        _Inout_ const FWPS_FILTER* filter)
{
  UNREFERENCED_PARAMETER(notifyType);
  UNREFERENCED_PARAMETER(filterKey);
  UNREFERENCED_PARAMETER(filter);

#if DEBUG
  DbgPrint("DatagramNotify()");
#endif

  return STATUS_SUCCESS;
}

void DatagramClassify(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
                      _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
                      _Inout_opt_ void* layerData,
#if(NTDDI_VERSION >= NTDDI_WIN7)
                      _In_opt_ const void* classifyContext,
#endif
                      _In_ const FWPS_FILTER* filter,
                      _In_ UINT64 flowContext,
                      _Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
  packet_t* packet;

#if(NTDDI_VERSION >= NTDDI_WIN7)
  UNREFERENCED_PARAMETER(classifyContext);
#endif

  UNREFERENCED_PARAMETER(filter);
  UNREFERENCED_PARAMETER(flowContext);

#if DEBUG
  DbgPrint("DatagramClassify()");
#endif

  /* ipHeaderSize is not applicable to the outbound path at the
   * FWPS_LAYER_DATAGRAM_DATA_V4/FWPS_LAYER_DATAGRAM_DATA_V6
   * layers.
   */
  if (FWPS_IS_METADATA_FIELD_PRESENT(
        inMetaValues,
        FWPS_METADATA_FIELD_IP_HEADER_SIZE
      )) {
    /* Get packet from the packet pool. */
    if ((packet = PopPacket()) != NULL) {
      if (FillPacket(inFixedValues, layerData, packet)) {
        if (!GivePacketToWorkerThread(packet)) {
          /* Return packet to packet pool. */
          PushPacket(packet);
        }
      } else {
        /* Return packet to packet pool. */
        PushPacket(packet);
      }
    }
  }

  classifyOut->actionType = FWP_ACTION_CONTINUE;
}


/*******************************************************************************
 *******************************************************************************
 **                                                                           **
 ** Closure.                                                                  **
 **                                                                           **
 *******************************************************************************
 *******************************************************************************/

NTSTATUS AleClosureNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                          _In_ const GUID* filterKey,
                          _Inout_ const FWPS_FILTER* filter)
{
  UNREFERENCED_PARAMETER(notifyType);
  UNREFERENCED_PARAMETER(filterKey);
  UNREFERENCED_PARAMETER(filter);

#if DEBUG
  DbgPrint("AleClosureNotify()");
#endif

  return STATUS_SUCCESS;
}

void AleClosureClassify(_In_ const FWPS_INCOMING_VALUES* inFixedValues,
                        _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
                        _Inout_opt_ void* layerData,
#if (NTDDI_VERSION >= NTDDI_WIN7)
                        _In_opt_ const void* classifyContext,
#endif
                        _In_ const FWPS_FILTER* filter,
                        _In_ UINT64 flowContext,
                        _Inout_ FWPS_CLASSIFY_OUT* classifyOut)
{
  packet_t* packet;

  UNREFERENCED_PARAMETER(inMetaValues);

#if(NTDDI_VERSION >= NTDDI_WIN7)
  UNREFERENCED_PARAMETER(classifyContext);
#endif

  UNREFERENCED_PARAMETER(filter);
  UNREFERENCED_PARAMETER(flowContext);

#if DEBUG
  DbgPrint("AleClosureClassify()");
#endif

  /* Get packet from the packet pool. */
  if ((packet = PopPacket()) != NULL) {
    if (FillPacket(inFixedValues, layerData, packet)) {
      if (!GivePacketToWorkerThread(packet)) {
        /* Return packet to packet pool. */
        PushPacket(packet);
      }
    } else {
      /* Return packet to packet pool. */
      PushPacket(packet);
    }
  }

  classifyOut->actionType = FWP_ACTION_CONTINUE;
}
