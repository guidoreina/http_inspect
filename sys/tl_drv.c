#include <ntddk.h>
#include <wdf.h>

#pragma warning(push)
#pragma warning(disable:4201) /* Unnamed struct/union. */

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>
#include "inspect.h"
#include "worker_thread.h"
#include "packet_pool.h"
#include "dnscache.h"
#include "logfile.h"

#define INITGUID
#include <guiddef.h>

#define NUMBER_BUCKETS 127
#define MAX_DNS_ENTRIES 1000
#define LOG_BUFFER_SIZE (8 * 1024)

typedef struct {
  const GUID* layerKey;
  const GUID* calloutKey;
  FWPS_CALLOUT_NOTIFY_FN notifyFn;
  FWPS_CALLOUT_CLASSIFY_FN classifyFn;
  wchar_t* name;
  wchar_t* description;
  UINT32* calloutId;
} callout_t;

/* Callout and sublayer GUIDs. */

/* 2e207682-d95f-4525-b966-969f26587f03 */
DEFINE_GUID(
  TL_INSPECT_SUBLAYER,
  0x2e207682,
  0xd95f,
  0x4525,
  0xb9, 0x66, 0x96, 0x9f, 0x26, 0x58, 0x7f, 0x03
);

/* 76b743d4-1249-4614-a632-6f9c4d08d25a */
DEFINE_GUID(
  TL_LAYER_STREAM_V4,
  0x76b743d4,
  0x1249,
  0x4614,
  0xa6, 0x32, 0x6f, 0x9c, 0x4d, 0x08, 0xd2, 0x5a
);

/* ac80683a-5b84-43c3-8ae9-eddb5c0d23c2 */
DEFINE_GUID(
  TL_LAYER_STREAM_V6,
  0xac80683a,
  0x5b84,
  0x43c3,
  0x8a, 0xe9, 0xed, 0xdb, 0x5c, 0x0d, 0x23, 0xc2
);

/* bb6e405b-19f4-4ff3-b501-1a3dc01aae01 */
DEFINE_GUID(
  TL_LAYER_DATAGRAM_V4,
  0xbb6e405b,
  0x19f4,
  0x4ff3,
  0xb5, 0x01, 0x1a, 0x3d, 0xc0, 0x1a, 0xae, 0x01
);

/* cabf7559-7c60-46c8-9d3b-2155ad5cf83f */
DEFINE_GUID(
  TL_LAYER_DATAGRAM_V6,
  0xcabf7559,
  0x7c60,
  0x46c8,
  0x9d, 0x3b, 0x21, 0x55, 0xad, 0x5c, 0xf8, 0x3f
);

/* 07248379-248b-4e49-bf07-24d99d52f8d0 */
DEFINE_GUID(
  TL_LAYER_ALE_EP_CLOSURE_V4,
  0x07248379,
  0x248b,
  0x4e49,
  0xbf, 0x07, 0x24, 0xd9, 0x9d, 0x52, 0xf8, 0xd0
);

/* 6d126434-ed67-4285-925c-cb29282e0e06 */
DEFINE_GUID(
  TL_LAYER_ALE_EP_CLOSURE_V6,
  0x6d126434,
  0xed67,
  0x4285,
  0x92, 0x5c, 0xcb, 0x29, 0x28, 0x2e, 0x0e, 0x06
);


static HANDLE hEngine;
static UINT32 layerStreamV4, layerStreamV6;
static UINT32 layerDatagramV4, layerDatagramV6;
static UINT32 layerAleClosureV4, layerAleClosureV6;

static callout_t callouts[] = {
  {
    &FWPM_LAYER_STREAM_V4,
    &TL_LAYER_STREAM_V4,
    StreamNotify,
    StreamClassify,
    L"StreamLayerV4",
    L"Intercepts the first outbound packet with payload of each connection.",
    &layerStreamV4
  },
  {
    &FWPM_LAYER_STREAM_V6,
    &TL_LAYER_STREAM_V6,
    StreamNotify,
    StreamClassify,
    L"StreamLayerV6",
    L"Intercepts the first outbound packet with payload of each connection.",
    &layerStreamV6
  },
  {
    &FWPM_LAYER_DATAGRAM_DATA_V4,
    &TL_LAYER_DATAGRAM_V4,
    DatagramNotify,
    DatagramClassify,
    L"DatagramLayerV4",
    L"Intercepts inbound UDP data.",
    &layerDatagramV4
  },
  {
    &FWPM_LAYER_DATAGRAM_DATA_V6,
    &TL_LAYER_DATAGRAM_V6,
    DatagramNotify,
    DatagramClassify,
    L"DatagramLayerV6",
    L"Intercepts inbound UDP data.",
    &layerDatagramV6
  },
  {
    &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,
    &TL_LAYER_ALE_EP_CLOSURE_V4,
    AleClosureNotify,
    AleClosureClassify,
    L"AleLayerEndpointClosureV4",
    L"Intercepts connection close",
    &layerAleClosureV4
  },
  {
    &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,
    &TL_LAYER_ALE_EP_CLOSURE_V6,
    AleClosureNotify,
    AleClosureClassify,
    L"AleLayerEndpointClosureV6",
    L"Intercepts connection close",
    &layerAleClosureV6
  }
};


DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;

static NTSTATUS AddFilter(_In_ const wchar_t* filterName,
                          _In_ const wchar_t* filterDesc,
                          _In_ UINT64 context,
                          _In_ const GUID* layerKey,
                          _In_ const GUID* calloutKey)
{
  FWPM_FILTER filter = {0};
  static const UINT16 PORTS[] = {80, 443, 53};
  FWPM_FILTER_CONDITION filterConditions[ARRAYSIZE(PORTS)];

  filter.displayData.name = (wchar_t*) filterName;
  filter.displayData.description = (wchar_t*) filterDesc;

  filter.rawContext = context;

  filter.layerKey = *layerKey;
  filter.action.calloutKey = *calloutKey;

  filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;

  for (size_t i = 0; i < ARRAYSIZE(PORTS); i++) {
    filterConditions[i].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    filterConditions[i].matchType = FWP_MATCH_EQUAL;
    filterConditions[i].conditionValue.type = FWP_UINT16;
    filterConditions[i].conditionValue.uint16 = PORTS[i];
  }

  filter.filterCondition = filterConditions;
  filter.numFilterConditions = ARRAYSIZE(PORTS);

  filter.subLayerKey = TL_INSPECT_SUBLAYER;
  filter.weight.type = FWP_EMPTY; /* Auto-weight. */

  return FwpmFilterAdd(hEngine, &filter, NULL, NULL);
}

static NTSTATUS RegisterCallout(_In_ const GUID* layerKey,
                                _In_ const GUID* calloutKey,
                                _Inout_ void* deviceObject,
                                _In_ FWPS_CALLOUT_NOTIFY_FN notifyFn,
                                _In_ FWPS_CALLOUT_CLASSIFY_FN classifyFn,
                                _In_ wchar_t* calloutName,
                                _In_ wchar_t* calloutDescription,
                                _Out_ UINT32* calloutId)
{
  FWPS_CALLOUT sCallout = {0};
  FWPM_CALLOUT mCallout = {0};
  NTSTATUS status;

  /* Register callout with the filter engine. */
  sCallout.calloutKey = *calloutKey;
  sCallout.notifyFn = notifyFn;
  sCallout.classifyFn = classifyFn;

  status = FwpsCalloutRegister(deviceObject, &sCallout, calloutId);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  /* Add callout. */
  mCallout.applicableLayer = *layerKey;
  mCallout.calloutKey = *calloutKey;
  mCallout.displayData.name = calloutName;
  mCallout.displayData.description = calloutDescription;

  status = FwpmCalloutAdd(hEngine, &mCallout, NULL, NULL);
  if (!NT_SUCCESS(status)) {
    FwpsCalloutUnregisterById(*calloutId);
    *calloutId = 0;

    return status;
  }

  /* Add filter. */
  status = AddFilter(L"HTTP/HTTPS/DNS",
                     L"Filter HTTP/HTTPS/DNS",
                     0,
                     layerKey,
                     calloutKey);

  if (!NT_SUCCESS(status)) {
    FwpsCalloutUnregisterById(*calloutId);
    *calloutId = 0;

    return status;
  }

  return STATUS_SUCCESS;
}

static NTSTATUS RegisterCallouts(_Inout_ void* deviceObject)
{
  FWPM_SESSION session = {0};
  FWPM_SUBLAYER TLInspectSubLayer;
  NTSTATUS status;

  /* If session.flags is set to FWPM_SESSION_FLAG_DYNAMIC, any WFP objects
   * added during the session are automatically deleted when the session ends.
   */
  session.flags = FWPM_SESSION_FLAG_DYNAMIC;

  /* Open session to the filter engine. */
  status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &hEngine);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  /* Begin transaction with the current session. */
  status = FwpmTransactionBegin(hEngine, 0);
  if (!NT_SUCCESS(status)) {
    FwpmEngineClose(hEngine);
    hEngine = NULL;

    return status;
  }

  /* Add sublayer to the system. */
  RtlZeroMemory(&TLInspectSubLayer, sizeof(FWPM_SUBLAYER));

  TLInspectSubLayer.subLayerKey = TL_INSPECT_SUBLAYER;
  TLInspectSubLayer.displayData.name = L"Transport Inspect Sub-Layer";
  TLInspectSubLayer.displayData.description =
    L"Sub-Layer for use by Transport Inspect callouts";

  TLInspectSubLayer.flags = 0;
  TLInspectSubLayer.weight = 0;

  status = FwpmSubLayerAdd(hEngine, &TLInspectSubLayer, NULL);
  if (!NT_SUCCESS(status)) {
    FwpmTransactionAbort(hEngine);
    _Analysis_assume_lock_not_held_(hEngine);

    FwpmEngineClose(hEngine);
    hEngine = NULL;

    return status;
  }

  /* Register callouts. */
  for (size_t i = 0; i < ARRAYSIZE(callouts); i++) {
    status = RegisterCallout(callouts[i].layerKey,
                             callouts[i].calloutKey,
                             deviceObject,
                             callouts[i].notifyFn,
                             callouts[i].classifyFn,
                             callouts[i].name,
                             callouts[i].description,
                             callouts[i].calloutId);

    if (!NT_SUCCESS(status)) {
      FwpmTransactionAbort(hEngine);
      _Analysis_assume_lock_not_held_(hEngine);

      FwpmEngineClose(hEngine);
      hEngine = NULL;

      return status;
    }
  }

  status = FwpmTransactionCommit(hEngine);

  if (!NT_SUCCESS(status)) {
    FwpmTransactionAbort(hEngine);
    _Analysis_assume_lock_not_held_(hEngine);

    FwpmEngineClose(hEngine);
    hEngine = NULL;

    return status;
  }

  return STATUS_SUCCESS;
}

static void UnregisterCallouts()
{
  FwpsCalloutUnregisterById(layerStreamV4);
  FwpsCalloutUnregisterById(layerStreamV6);
  FwpsCalloutUnregisterById(layerDatagramV4);
  FwpsCalloutUnregisterById(layerDatagramV6);
  FwpsCalloutUnregisterById(layerAleClosureV4);
  FwpsCalloutUnregisterById(layerAleClosureV6);

  FwpmEngineClose(hEngine);
  hEngine = NULL;
}

_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void EvtDriverUnload(_In_ WDFDRIVER driverObject)
{
  UNREFERENCED_PARAMETER(driverObject);

  UnregisterCallouts();
  StopWorkerThread();
  FreeWorkerThread();
  CloseLogFile();
  FreeDnsCache();
  FreePacketPool();
}

static NTSTATUS InitDriverObjects(_Inout_ DRIVER_OBJECT* driverObject,
                                  _In_ const UNICODE_STRING* registryPath,
                                  _Out_ WDFDRIVER* pDriver,
                                  _Out_ WDFDEVICE* pDevice)
{
  WDF_DRIVER_CONFIG config;
  NTSTATUS status;

  /* Initialize 'config'. */
  WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
  config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
  config.EvtDriverUnload = EvtDriverUnload;

  /* Create framework driver object. */
  status = WdfDriverCreate(driverObject,
                           registryPath,
                           WDF_NO_OBJECT_ATTRIBUTES,
                           &config,
                           pDriver);

  if (!NT_SUCCESS(status)) {
    return status;
  }

  /* Allocate a WDFDEVICE_INIT structure. */
  PWDFDEVICE_INIT pInit =
                    WdfControlDeviceInitAllocate(*pDriver,
                                                 &SDDL_DEVOBJ_KERNEL_ONLY);

  if (!pInit) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  WdfDeviceInitSetDeviceType(pInit, FILE_DEVICE_NETWORK);
  WdfDeviceInitSetCharacteristics(pInit, FILE_DEVICE_SECURE_OPEN, FALSE);
  WdfDeviceInitSetCharacteristics(pInit, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

  /* Create framework device object. */
  status = WdfDeviceCreate(&pInit, WDF_NO_OBJECT_ATTRIBUTES, pDevice);
  if (!NT_SUCCESS(status)) {
    WdfDeviceInitFree(pInit);
    return status;
  }

  /* Inform framework that we have finished initializing the device object. */
  WdfControlFinishInitializing(*pDevice);

  return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(DRIVER_OBJECT* driverObject, UNICODE_STRING* registryPath)
{
  WDFDRIVER driver;
  WDFDEVICE device;
  DEVICE_OBJECT* wdmDevice;
  WDFKEY parametersKey;
  NTSTATUS status;

  /* Request NX Non-Paged Pool when available. */
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

  /* Initialize packet pool. */
  if (!InitPacketPool(MAX_PACKETS, MAX_PACKET_SIZE)) {
    DbgPrint("Error initializing packet pool.");
    return STATUS_NO_MEMORY;
  }

  /* Initialize DNS cache. */
  if (!InitDnsCache(NUMBER_BUCKETS, MAX_DNS_ENTRIES)) {
    DbgPrint("Error initializing DNS cache.");

    FreePacketPool();
    return STATUS_NO_MEMORY;
  }

  /* Open log file. */
  status = OpenLogFile(LOG_BUFFER_SIZE);
  if (!NT_SUCCESS(status)) {
    DbgPrint("Error opening log file.");

    FreeDnsCache();
    FreePacketPool();

    return status;
  }

  /* Initialize worker thread. */
  if (!InitWorkerThread(MAX_PACKETS)) {
    DbgPrint("Error initializing worker thread.");

    CloseLogFile();
    FreeDnsCache();
    FreePacketPool();

    return STATUS_NO_MEMORY;
  }

  /* Start worker thread. */
  status = StartWorkerThread();
  if (!NT_SUCCESS(status)) {
    DbgPrint("Error starting worker thread.");

    FreeWorkerThread();
    CloseLogFile();
    FreeDnsCache();
    FreePacketPool();

    return status;
  }

  /* Initialize driver objects. */
  status = InitDriverObjects(driverObject, registryPath, &driver, &device);
  if (!NT_SUCCESS(status)) {
    StopWorkerThread();
    FreeWorkerThread();
    CloseLogFile();
    FreeDnsCache();
    FreePacketPool();

    return status;
  }

  /* Open 'Parameters' registry key and retrieve a handle to the registry-key
   * object.
   */
  status = WdfDriverOpenParametersRegistryKey(driver,
                                              KEY_READ,
                                              WDF_NO_OBJECT_ATTRIBUTES,
                                              &parametersKey);

  if (!NT_SUCCESS(status)) {
    StopWorkerThread();
    FreeWorkerThread();
    CloseLogFile();
    FreeDnsCache();
    FreePacketPool();

    return status;
  }

  /* Get the Windows Driver Model (WDM) device object. */
  wdmDevice = WdfDeviceWdmGetDeviceObject(device);

  /* Register callouts. */
  status = RegisterCallouts(wdmDevice);
  if (!NT_SUCCESS(status)) {
    UnregisterCallouts();
    StopWorkerThread();
    FreeWorkerThread();
    CloseLogFile();
    FreeDnsCache();
    FreePacketPool();

    return status;
  }

  return STATUS_SUCCESS;
}
