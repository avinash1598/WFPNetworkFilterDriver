/*
	User-mode header file names end in "u" and kernel-mode header file names end in "k"

	Here filtering is performed at sublayer level
*/

//#include <ntddk.h>
#include <ntifs.h>
#include <wdf.h>
#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union
#include <fwpmk.h> //kernel mode WFP functions
#include <fwpsk.h>
#pragma warning(pop)
#define INITGUID
#include <guiddef.h>
#include <ntintsafe.h>
#include <netiodef.h>

#define STREAM_BUFFER_POOL_TAG 'bfeS'
#define HLPR_NEW_ARRAY(pPtr, object, count, tag)               \
   for(;                                                       \
       pPtr == 0;                                              \
      )                                                        \
   {                                                           \
      size_t SAFE_SIZE = 0;                                    \
      if(count &&                                              \
         RtlSizeTMult(sizeof(object),                          \
                      (size_t)count,                           \
                      &SAFE_SIZE) == STATUS_SUCCESS &&         \
         SAFE_SIZE >= (sizeof(object) * count))                \
      {                                                        \
         pPtr = (object*)ExAllocatePoolWithTag(NonPagedPoolNx, \
                                               SAFE_SIZE,      \
                                               tag);           \
         if(pPtr)                                              \
            RtlZeroMemory(pPtr,                                \
                          SAFE_SIZE);                          \
      }                                                        \
      else                                                     \
      {                                                        \
         pPtr = 0;                                             \
         break;                                                \
      }                                                        \
   }

#define HLPR_DELETE_ARRAY(pPtr, tag)       \
   if(pPtr)                          \
   {                                 \
      ExFreePoolWithTag((VOID*)pPtr, \
                        tag);        \
      pPtr = 0;                      \
   }

#define htonl(x) (((((ULONG)(x))&0xffL)<<24) | \
((((ULONG)(x))&0xff00L)<<8) | \
((((ULONG)(x))&0xff0000L)>>8) | \
((((ULONG)(x))&0xff000000L)>>24))

//96ebd471-62ea-4b06-8c3e-33ab71b6c6d7
DEFINE_GUID
(
	STREAM_VIEW_STREAM_CALLOUT_V4,
	0x96ebd471,
	0x62ea,
	0x4b06,
	0x8c, 0x3e, 0x33, 0xab, 0x71, 0xb6, 0xc6, 0xd7
);

//e69fd434-1b88-4334-b207-7ac1e8d3fd97
DEFINE_GUID
(
	WFP_SAMPLE_SUBLAYER_GUID,
	0xe69fd434,
	0x1b88, 
	0x4334,
	0xb2, 0x07, 0x7a, 0xc1, 0xe8, 0xd3, 0xfd, 0x97
);

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD DeriverUnload;
HANDLE FilterEngineHandle;
PDEVICE_OBJECT gWdmDevice;
HANDLE gInjectionHandle;

UINT32 RegCalloutId = 0;
UINT32 AddCalloutId = 0;
UINT64 FilterId = 0;

UnInitializeWfp()
{
	KdPrint(("MyNetworkFilter: Uninitializing WFP"));

	if (FilterEngineHandle != NULL)
	{
		if (FilterId != 0)
		{
			FwpmFilterDeleteById(FilterEngineHandle, FilterId);
		}

		FwpmSubLayerDeleteByKey(FilterEngineHandle, &WFP_SAMPLE_SUBLAYER_GUID);

		if (AddCalloutId != 0)
		{
			FwpmCalloutDeleteById(FilterEngineHandle, AddCalloutId);
		}

		if (RegCalloutId != 0)
		{
			FwpsCalloutUnregisterById(RegCalloutId);
		}

		FwpmEngineClose(FilterEngineHandle);
	}
}

DriverUnload
(
	_In_ WDFDRIVER driver
)
{
	KdPrint(("MyNetworkFilter: Unloading Driver... \n"));
	//TODO: perform unregister operations when the driver unloads

	UnInitializeWfp();
	UNREFERENCED_PARAMETER(driver);

	KdPrint(("MyNetworkFilter: Driver unloaded. Bye-:) \n"));
}

/*
	Initialize driver and device
*/
NTSTATUS
InitDriverObjects(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath,
	WDFDRIVER* driver,
	WDFDEVICE* device 
)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;
	PWDFDEVICE_INIT pDeviceInit = NULL;

	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

	//unregister everything when the driver unloads using EvtDriverUnload callback
	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = DriverUnload;

	KdPrint(("MyNetworkFilter: Creating Driver... \n"));

	status = WdfDriverCreate(
				pDriverObject,
				pRegistryPath,
				WDF_NO_OBJECT_ATTRIBUTES,
				&config,
				driver
			);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	KdPrint(("MyNetworkFilter: Successfully created driver. \n"));

	KdPrint(("MyNetworkFilter: Allocating Device... \n"));

	/*
		Allocating resource(device) to driver
		SDDL_DEVOBJ_KERNEL_ONLY is the "empty" ACL. 
		User-mode code (including processes running as system) cannot open the device.
	*/
	pDeviceInit = WdfControlDeviceInitAllocate(*driver, &SDDL_DEVOBJ_KERNEL_ONLY);

	if (!pDeviceInit)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	KdPrint(("MyNetworkFilter: InitDriverObjects: Successfully Allocated Device. \n"));

	KdPrint(("MyNetworkFilter: InitDriverObjects: Creating Device... \n"));

	//WdfDeviceInitSetCharacteristics(pDeviceInit, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);
	WdfDeviceInitSetDeviceType(pDeviceInit, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(pDeviceInit, FILE_DEVICE_SECURE_OPEN, TRUE);

	status = WdfDeviceCreate(
				&pDeviceInit,
				WDF_NO_OBJECT_ATTRIBUTES,
				device
			);

	if (!NT_SUCCESS(status))
	{
		//Free device allocation
		WdfDeviceInitFree(pDeviceInit);
		goto Exit;
	}

	WdfControlFinishInitializing(*device);

	KdPrint(("MyNetworkFilter: Successfully created device. \n"));

Exit:

	if (!NT_SUCCESS(status))
	{
		//KdPrint(("MyNetworkFilter: DriverEntry -> InitDriverObjects -> Exiting. \n"));
	}
	
	return status;
}

VOID NBLCpyToBuffer(
	NET_BUFFER_LIST* pStreamNBL
)
{
	if (pStreamNBL) 
	{
		KdPrint(("Starting NBL data processing... \n"));
		//get frame type and check
		for (NET_BUFFER* pNB = NET_BUFFER_LIST_FIRST_NB(pStreamNBL); pNB; pNB = NET_BUFFER_NEXT_NB(pNB))
		{
			BYTE* pContiguousBuffer = 0;
			BYTE* pAllocatedBuffer = 0;
			UINT32 bytesNeeded = NET_BUFFER_DATA_LENGTH(pNB);
			BYTE* ethernetFrame = 0;
			UINT32 dataOffset = NET_BUFFER_DATA_OFFSET(pNB);
			UINT32 MAC_HEADER_LENGTH = 14; // 14 to 22
			UINT32 IPV4_HEADER_LENGTH = 20;
			KdPrint(("NB size %d \n", bytesNeeded));
			KdPrint(("Dataoffset %d \n", dataOffset));
			if (bytesNeeded) 
			{
				HLPR_NEW_ARRAY(pAllocatedBuffer, 
					BYTE, bytesNeeded, STREAM_BUFFER_POOL_TAG);
				if (pAllocatedBuffer)
				{
					KdPrint(("Copied buffer \n"));
					pContiguousBuffer = (BYTE*)NdisGetDataBuffer(pNB, 
						bytesNeeded, pAllocatedBuffer, 1, 0);
					ethernetFrame = pContiguousBuffer ? pContiguousBuffer : pAllocatedBuffer;
					
					/*for (UINT32 i = dataOffset; i < bytesNeeded; i++)
					{	
						UCHAR c = ipHeader[i];
						KdPrint(("Byte value : %d \n", c));
					}
					/*
					* Protocol offset : 9 (1 byte)
					* Source Ip offset : 12 (4 bytes)
					* Destination Ip Offset : 16 (4 bytes)
					* 14 bytes needed at the start for ethernet header : 
					*	added offset for  above offsets 
					*/
					UCHAR p1 = ethernetFrame[dataOffset + MAC_HEADER_LENGTH + 12];
					UCHAR p2 = ethernetFrame[dataOffset + MAC_HEADER_LENGTH + 13];
					UCHAR p3 = ethernetFrame[dataOffset + MAC_HEADER_LENGTH + 14];
					UCHAR p4 = ethernetFrame[dataOffset + MAC_HEADER_LENGTH + 15];
					UCHAR p5 = ethernetFrame[dataOffset + MAC_HEADER_LENGTH + 16];
					UCHAR p6 = ethernetFrame[dataOffset + MAC_HEADER_LENGTH + 17];
					UCHAR p7 = ethernetFrame[dataOffset + MAC_HEADER_LENGTH + 18];
					UCHAR p8 = ethernetFrame[dataOffset + MAC_HEADER_LENGTH + 19];

					KdPrint(("Src IP : %d.%d.%d.%d  Dest IP : %d.%d.%d.%d \n", 
						p1, p2, p3, p4, p5, p6, p7, p8));

					UINT16 sp = ((ethernetFrame[dataOffset + MAC_HEADER_LENGTH + IPV4_HEADER_LENGTH] & 0xff) << 8)
						| ((ethernetFrame[dataOffset + MAC_HEADER_LENGTH + IPV4_HEADER_LENGTH + 1]) & 0xff);
					UINT16 dp = ((ethernetFrame[dataOffset + MAC_HEADER_LENGTH + IPV4_HEADER_LENGTH + 2] & 0xff) << 8)
						| ((ethernetFrame[dataOffset + MAC_HEADER_LENGTH + IPV4_HEADER_LENGTH + 3]) & 0xff);

					KdPrint(("Src Port : %d  Remote PORT : %d \n", sp, dp));
				}
				HLPR_DELETE_ARRAY(pAllocatedBuffer,
					STREAM_BUFFER_POOL_TAG);
			}
		}
	}
	else 
	{
		KdPrint(("Failed to start NBL data processing!!! \n\n"));
	}
}

VOID stringifyContent(
	NET_BUFFER_LIST* pStreamNBL
)
{
	if (pStreamNBL)
	{
		KdPrint(("Starting NBL data processing... \n"));
		//get frame type and check
		for (NET_BUFFER* pNB = NET_BUFFER_LIST_FIRST_NB(pStreamNBL); pNB; pNB = NET_BUFFER_NEXT_NB(pNB))
		{
			BYTE* pContiguousBuffer = 0;
			BYTE* pAllocatedBuffer = 0;
			UINT32 bytesNeeded = NET_BUFFER_DATA_LENGTH(pNB);
			BYTE* streamData = 0;
			//UINT32 dataOffset = NET_BUFFER_DATA_OFFSET(pNB);
			
			KdPrint(("NB size %d \n", bytesNeeded));
			if (bytesNeeded)
			{
				HLPR_NEW_ARRAY(pAllocatedBuffer,
					BYTE, bytesNeeded, STREAM_BUFFER_POOL_TAG);
				if (pAllocatedBuffer)
				{
					//KdPrint(("Copied buffer \n"));
					pContiguousBuffer = (BYTE*)NdisGetDataBuffer(pNB,
						bytesNeeded, pAllocatedBuffer, 1, 0);
					streamData = pContiguousBuffer ? pContiguousBuffer : pAllocatedBuffer;

					KdPrint(("TCP Packet: %s \n", streamData));
				}
				HLPR_DELETE_ARRAY(pAllocatedBuffer,
					STREAM_BUFFER_POOL_TAG);
			}
		}
	}
	else
	{
		KdPrint(("Failed to start NBL data processing!!! \n\n"));
	}
}

VOID
ModifyPacket()
{
}

VOID
ClassifyCallback
(	
	const FWPS_INCOMING_VALUES0* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	VOID* layerData,
	const FWPS_FILTER0* filter,
	UINT64  flowContext,
	FWPS_CLASSIFY_OUT0* classifyOut
)
{
	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	//UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	//UNREFERENCED_PARAMETER(classifyOut);

	//KdPrint(("ClassifyCallback -> Stream data is here. \n"));

	//PNET_BUFFER_LIST rawData;

	FWPS_STREAM_CALLOUT_IO_PACKET* ioPacket;
	FWPS_STREAM_DATA* dataStream;
	PNET_BUFFER_LIST pNBL;

	//UCHAR buffer[201] = { 0 };
	//SIZE_T length = 0;
	//SIZE_T bytes;

	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		// Return without specifying an action
		return;
	}
	
	ULONG remoteIpAddress = htonl(inFixedValues->incomingValue
		[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32);
	/*ULONG localIpAddress = htonl(inFixedValues->incomingValue[
		FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value.uint32);*/
	
	ULONG orderedRemoteIP = ((remoteIpAddress >> 24) & 0xff) | // move byte 3 to byte 0
							((remoteIpAddress << 8) & 0xff0000) | // move byte 1 to byte 2
							((remoteIpAddress >> 8) & 0xff00) | // move byte 2 to byte 1
							((remoteIpAddress << 24) & 0xff000000); // byte 0 to byte 3

	/*ULONG orderedLocalIP = ((localIpAddress >> 24) & 0xff) | // move byte 3 to byte 0
						   ((localIpAddress << 8) & 0xff0000) | // move byte 1 to byte 2
						   ((localIpAddress >> 8) & 0xff00) | // move byte 2 to byte 1
						   ((localIpAddress << 24) & 0xff000000); // byte 0 to byte 3*/

	//UCHAR* temp = (PUCHAR)(&(orderedRemoteIP));
	
	KdPrint(("\nRemote IP : %d.%d.%d.%d \n", ((orderedRemoteIP >> 24) & 0xff), 
										        ((orderedRemoteIP >> 16) & 0xff),
										        ((orderedRemoteIP >> 8) & 0xff),
										        ((orderedRemoteIP >> 0) & 0xff)));
	
	ioPacket = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;
	dataStream = ioPacket->streamData;
	
	//pNBL = (NET_BUFFER_LIST*)layerData;
	//stringifyContent(pNBL);
	//KdPrint(("Received Packet Data. \n"));
	
	if (dataStream->flags & FWPS_STREAM_FLAG_RECEIVE)
	{
		//length = dataStream->dataLength <= 200 ? dataStream->dataLength*sizeof(UCHAR) : 200*sizeof(UCHAR);
		//length = dataStream->dataLength*sizeof(UCHAR); // throws buffer overrun error
		//FwpsCopyStreamDataToBuffer0(dataStream, buffer, length, &bytes);
		//KdPrint(("Packet Data: \n\n %s \r\n\n", buffer));

		KdPrint(("Received Packet Data. \n"));
		pNBL = dataStream->netBufferListChain;
		stringifyContent(pNBL);
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;

	// Check whether the FWPS_RIGHT_ACTION_WRITE flag should be cleared
	if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
	{
		// Clear the FWPS_RIGHT_ACTION_WRITE flag
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}
}
/*
void
NTAPI
InjectionCompletionFn(
	IN void* context,
	IN OUT NET_BUFFER_LIST* netBufferList,
	IN BOOLEAN dispatchLevel
)
{
	FWPS_TRANSPORT_SEND_PARAMS0* tlSendArgs
		= (FWPS_TRANSPORT_SEND_PARAMS0*)context;

	//
	// TODO: Free tlSendArgs and embedded allocations.
	//

	//
	// TODO: Check netBufferList->Status for injection result
	//

	FwpsFreeCloneNetBufferList0(netBufferList, 0);

	KdPrint(("On Packet Injection Completion. \n"));
}

void
NTAPI
WfpTransportSendClassify(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const FWPS_FILTER0* filter,
	IN UINT64 flowContext,
	IN OUT FWPS_CLASSIFY_OUT0* classifyOut
)
{
	NTSTATUS status;

	NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)layerData;
	NET_BUFFER_LIST* clonedNetBufferList = NULL;
	FWPS_PACKET_INJECTION_STATE injectionState;
	FWPS_TRANSPORT_SEND_PARAMS0* tlSendArgs = NULL;
	ADDRESS_FAMILY af = AF_UNSPEC;
	
	BYTE* remoteIpAddress = htonl(inFixedValues->incomingValue
		[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32);
	BYTE* localIpAddress = htonl(inFixedValues->incomingValue[
		FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value.uint32);

	KdPrint(("Remote IP : %s  Local IP : %s \n", remoteIpAddress, localIpAddress));

	injectionState = FwpsQueryPacketInjectionState0(
		gInjectionHandle,
		netBufferList,
		NULL);
	if (injectionState == FWPS_PACKET_INJECTED_BY_SELF ||
		injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
	{
		classifyOut->actionType = FWP_ACTION_PERMIT;
		goto Exit;
	}

	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
	{
		//
		// Cannot alter the action.
		//
		goto Exit;
	}

	//
	// TODO: Allocate and populate tlSendArgs by using information from
	// inFixedValues and inMetaValues.
	// Note: 1) Remote address and controlData (if not NULL) must
	// be deep-copied.
	//       2) IPv4 address must be converted to network order.
	//       3) Handle allocation errors.

	tlSendArgs->remoteAddress = (PUCHAR)(&(remoteIpAddress));(currently in reversed order)
	tlSendArgs->remoteScopeId = inMetaValues->remoteScopeId;
	if (inMetaValues->controlData) 
	{
		tlSendArgs->controlDataLength = inMetaValues->controlDataLength;
		RtlCopyMemory(tlSendArgs->controlData, inMetaValues->controlData, 
			inMetaValues->controlDataLength);
	}
	
	ASSERT(tlSendArgs != NULL);

	status = FwpsAllocateCloneNetBufferList0(
		netBufferList,
		NULL,
		NULL,
		0,
		&clonedNetBufferList);

	if (!NT_SUCCESS(status))
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

		goto Exit;
	}

	// 
	// TODO: Perform modification to the cloned net buffer list here.
	//

	//
	// TODO: Set af based on inFixedValues->layerId.
	//
	ASSERT(af == AF_INET || af == AF_INET6);

	//
	// Note: For TCP traffic, FwpsInjectTransportReceiveAsync0 and
	// FwpsInjectTransportSendAsync0 must be queued and run by a DPC.
	//

	status = FwpsInjectTransportSendAsync0(
		gInjectionHandle,
		NULL,
		inMetaValues->transportEndpointHandle,
		0,
		tlSendArgs,
		af,
		inMetaValues->compartmentId,
		clonedNetBufferList,
		InjectionCompletionFn,
		tlSendArgs);

	if (!NT_SUCCESS(status))
	{
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

		goto Exit;
	}

	classifyOut->actionType = FWP_ACTION_BLOCK;
	classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

	//
	// Ownership of clonedNetBufferList and tlSendArgs
	// now transferred to InjectionCompletionFn.
	//
	clonedNetBufferList = NULL;
	tlSendArgs = NULL;

Exit:

	if (clonedNetBufferList != NULL)
	{
		FwpsFreeCloneNetBufferList0(clonedNetBufferList, 0);
	}
	if (tlSendArgs != NULL)
	{
		//
		// TODO: Free tlSendArgs and embedded allocations.
		//
	}

	return;
}
*/
NTSTATUS
NotifyCallback
(	
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID* filterKey,
	const FWPS_FILTER0* filter
)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}

NTSTATUS
FlowDeleteCallback
(
	UINT16  layerId,
	UINT32  calloutId,
	UINT64  flowContext
)
{
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);

	return STATUS_SUCCESS;
}

NTSTATUS
WfpRegisterCallout()
{
	FWPS_CALLOUT0 sCallout = {0};

	sCallout.calloutKey = STREAM_VIEW_STREAM_CALLOUT_V4;
	sCallout.flags = 0;
	sCallout.classifyFn = ClassifyCallback; //WfpTransportSendClassify
	sCallout.notifyFn = NotifyCallback;
	sCallout.flowDeleteFn = FlowDeleteCallback;

	return FwpsCalloutRegister0(gWdmDevice, &sCallout, &RegCalloutId);

}

NTSTATUS
WfpAddCallout()
{
	FWPM_CALLOUT mCallout = { 0 };
	
	mCallout.flags = 0;
	mCallout.displayData.name = L"RanjanNetworkFilterWfpCallout";
	mCallout.displayData.description = L"RanjanNetworkFilterWfpCallout";
	//mCallout.calloutId = RegCalloutId;
	mCallout.calloutKey = STREAM_VIEW_STREAM_CALLOUT_V4;
	mCallout.applicableLayer = FWPM_LAYER_STREAM_V4;
	
	return FwpmCalloutAdd(FilterEngineHandle, &mCallout, NULL, &AddCalloutId);
}

NTSTATUS
WfpAddSublayer()
{
	FWPM_SUBLAYER mSubLayer = { 0 };

	mSubLayer.flags = 0;
	mSubLayer.displayData.name = L"RanjanNetworkFilterWfpSubLayer";
	mSubLayer.displayData.description = L"RanjanNetworkFilterWfpSubLayer";
	mSubLayer.subLayerKey = WFP_SAMPLE_SUBLAYER_GUID;
	mSubLayer.weight = 65500;

	return FwpmSubLayerAdd(FilterEngineHandle, &mSubLayer, NULL);
}

NTSTATUS
WfpAddFilter()
{
	FWPM_FILTER mFilter = { 0 };
	FWPM_FILTER_CONDITION filterConditions[1] = { 0 };

	mFilter.displayData.name = L"RanjanNetworkFilterWfpFilter";
	mFilter.displayData.description = L"RanjanNetworkFilterWfpFilter";
	mFilter.layerKey = FWPM_LAYER_STREAM_V4; //this will give tcp stream data
	//mFilter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
	//mFilter.layerKey = FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET; //this will give ethernet frame
	mFilter.subLayerKey = WFP_SAMPLE_SUBLAYER_GUID;
	mFilter.weight.type = FWP_EMPTY; // auto-weight.
	mFilter.numFilterConditions = 1;
	mFilter.filterCondition = filterConditions;
	mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;// (Not available at datagram layer) 
	//Transfer packet to callout -> FWP_ACTION_CALLOUT_INSPECTION, FWP_ACTION_CALLOUT_TERMINATING
	mFilter.action.calloutKey = STREAM_VIEW_STREAM_CALLOUT_V4;

	filterConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
	filterConditions[0].matchType = FWP_MATCH_EQUAL;
	filterConditions[0].conditionValue.type = FWP_UINT16;
	filterConditions[0].conditionValue.uint16 = 80;

	//filterConditions[0].fieldKey = FWPM_CONDITION_ETHER_TYPE;
	//filterConditions[0].matchType = FWP_MATCH_EQUAL;
	//filterConditions[0].conditionValue.type = FWP_UINT16;
	//filterConditions[0].conditionValue.uint16 = ETHERNET_TYPE_IPV4;

	//filterConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	//filterConditions[0].matchType = FWP_MATCH_EQUAL;
	//filterConditions[0].conditionValue.type = FWP_UINT32;
	//filterConditions[0].conditionValue.uint32 = 168120085;

	return FwpmFilterAdd(FilterEngineHandle, &mFilter, NULL, &FilterId);
}

/*
	Initialize Windows Filtering Platform
*/
NTSTATUS
InitializeWfp() 
{
	NTSTATUS status;

	//1 -> open filter engine
	KdPrint(("MyNetworkFilter: Opening Filter engine... \n"));	
	status = FwpmEngineOpen0(
				NULL,
				RPC_C_AUTHN_WINNT,
				NULL,
				NULL,
				&FilterEngineHandle
			);

	if (!NT_SUCCESS(status))
		goto Exit;

	KdPrint(("MyNetworkFilter: Successfully obtained Filter Engine Handle. \n"));

	//2 -> Register callout
	KdPrint(("MyNetworkFilter: Registering Callout... \n"));
	status = WfpRegisterCallout();
	
	if (!NT_SUCCESS(status))
		goto Exit;  

	KdPrint(("MyNetworkFilter: Successfully Registered Callout.\n"));

	//3 -> add callout to engine
	KdPrint(("MyNetworkFilter: Adding callout to the filter engine...\n"));
	status = WfpAddCallout();

	if (!NT_SUCCESS(status))
		goto Exit;

	KdPrint(("MyNetworkFilter: Successfully added callout to the filter engine.\n"));

	//4 -> add sublayer to engine
	KdPrint(("MyNetworkFilter: Adding sublayer to the filter engine...\n"));
	status = WfpAddSublayer();

	if (!NT_SUCCESS(status))
		goto Exit;

	KdPrint(("MyNetworkFilter: Successfully added sublayer to the filter engine.\n"));

	//5 -> add filter to layer
	KdPrint(("MyNetworkFilter: Adding filter to the filter engine...\n"));
	status = WfpAddFilter();

	if (!NT_SUCCESS(status))
		goto Exit;

	KdPrint(("MyNetworkFilter: Successfully added filter to the filter engine.\n"));

Exit:

	if (!NT_SUCCESS(status))
	{
		UnInitializeWfp();
	}

	return status;
}

/*
	PDRIVER_OBJECT => DRIVER_OBJECT*
*/
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT pDriverObject,
	_In_ PUNICODE_STRING pRegistryPath
)
{
	//STEP1 -----> Create driver object and device object
	NTSTATUS status;
	WDFDEVICE device = NULL;
	WDFDRIVER driver = NULL;

	UNREFERENCED_PARAMETER(device);
	UNREFERENCED_PARAMETER(device);

	KdPrint(("MyNetworkFilter: Initializing driver & device.... \n"));

	status = InitDriverObjects(
				pDriverObject,
				pRegistryPath,
				&driver,
				&device
			);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	KdPrint(("MyNetworkFilter: Initializing driver & device successful. \n"));

	//STEP2 -----> Initialize Windows Filtering Platform

	//get wdm device instance from wdf instance type

	gWdmDevice = WdfDeviceWdmGetDeviceObject(device);

	status = InitializeWfp();

	if (!NT_SUCCESS(status))
	{
		//TODO: delete device object
		goto Exit;
	}

	KdPrint(("MyNetworkFilter: Wfp initialization successful. \n"));

Exit:

	return status;
}