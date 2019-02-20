#ifndef UTILS_H
#define UTILS_H

__inline ADDRESS_FAMILY GetAddressFamilyForLayer(_In_ UINT16 layerId)
{
  switch (layerId)
  {
    case FWPS_LAYER_STREAM_V4:
    case FWPS_LAYER_DATAGRAM_DATA_V4:
    case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4:
      return AF_INET;
    case FWPS_LAYER_STREAM_V6:
    case FWPS_LAYER_DATAGRAM_DATA_V6:
    case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6:
      return AF_INET6;
    default:
      return AF_UNSPEC;
  }
}

__inline BOOL GetNetwork4TupleIndexesForLayer(_In_ UINT16 layerId,
                                              _Out_ UINT* localAddressIndex,
                                              _Out_ UINT* remoteAddressIndex,
                                              _Out_ UINT* localPortIndex,
                                              _Out_ UINT* remotePortIndex)
{
  switch (layerId)
  {
    case FWPS_LAYER_STREAM_V4:
      *localAddressIndex = FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT;
      return TRUE;
    case FWPS_LAYER_STREAM_V6:
      *localAddressIndex = FWPS_FIELD_STREAM_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_STREAM_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_STREAM_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_STREAM_V6_IP_REMOTE_PORT;
      return TRUE;
    case FWPS_LAYER_DATAGRAM_DATA_V4:
      *localAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT;
      return TRUE;
    case FWPS_LAYER_DATAGRAM_DATA_V6:
      *localAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT;
      return TRUE;
    case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4:
      *localAddressIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_PORT;
      return TRUE;
    case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6:
      *localAddressIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_LOCAL_ADDRESS;
      *remoteAddressIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_REMOTE_ADDRESS;
      *localPortIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_LOCAL_PORT;
      *remotePortIndex = FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_REMOTE_PORT;
      return TRUE;
    default:
      return FALSE;
  }
}

#endif /* UTILS_H */
