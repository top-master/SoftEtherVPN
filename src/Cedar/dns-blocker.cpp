// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// dns-blocker.cpp
// DNS leak blocker for Win32 VPN client sessions

#ifdef OS_WIN32

#include "dns-blocker_p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef strcmpi
#define strcmpi _stricmp
#endif


HINSTANCE DnsBlockerPrivate::ipLibrary = NULL;

ConvertInterfaceIndexToLuidPtr
	DnsBlockerPrivate::convertInterfaceIndexToLuid = NULL;

GetAdaptersInfoPtr DnsBlockerPrivate::getAdaptersInfo = NULL;

static bool IsSoftEtherAdapter(const char *description)
{
	if (description == NULL)
	{
		return false;
	}

	// Note: use `strcmpi` if `_strnicmp` is unavailable.
	if (_strnicmp(description, VLAN_ADAPTER_NAME, strlen(VLAN_ADAPTER_NAME)) == 0)
	{
		return true;
	}

	if (_strnicmp(description, VLAN_ADAPTER_NAME_OLD, strlen(VLAN_ADAPTER_NAME_OLD)) == 0)
	{
		return true;
	}

	return false;
}


DnsBlocker::DnsBlocker()
	: d(new DnsBlockerPrivate())
{
}

DnsBlocker::~DnsBlocker()
{
	this->stop();
	delete d;
}

void DnsBlocker::prepare()
{
	if (d->api == NULL)
	{
		d->api = ::IPsecWin7GetApi();
	}

	if (d->ipLibrary == NULL)
	{
		d->ipLibrary = ::LoadLibraryA("Iphlpapi.DLL");
		if (d->ipLibrary != NULL)
		{
			d->convertInterfaceIndexToLuid = reinterpret_cast<ConvertInterfaceIndexToLuidPtr>(
					::GetProcAddress(d->ipLibrary, "ConvertInterfaceIndexToLuid")
				);
			d->getAdaptersInfo = reinterpret_cast<GetAdaptersInfoPtr>(
					::GetProcAddress(d->ipLibrary, "GetAdaptersInfo")
				);
		}
	}

	// Restore to DHCP from possible Static-DNS (for Windows-XP)
	// since this service might be crashed last time before doing so
	if (this->isFilterable() == false)
	{
		this->stop();
	}
}

void DnsBlocker::start()
{
	if (this->isFilterable())
	{
		FWPM_SESSION0 session;
		::memset(&session, 0, sizeof(session));

		// Create/Open a new dynamic-session to the filter-engine which
		// once closed, will undo all our filter-conditions
		session.flags = FWPM_SESSION_FLAG_DYNAMIC;

		DWORD err = d->api->FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &d->engine);
		if (err == ERROR_SUCCESS)
		{
			// Create and add persistent packet-filter sublayer to the system
			FWPM_SUBLAYER0 layer;
			::memset(&layer, 0, sizeof(layer));

			// Load GUID for our layer
			layer.subLayerKey = DnsBlockerGuid;
			layer.displayData.name = const_cast<wchar_t *>(DNSBLOCKER_LAYER_NAME_W);
			layer.displayData.description = const_cast<wchar_t *>(DNSBLOCKER_LAYER_NAME_W);
			layer.flags = 0;
			layer.weight = 0x100;

			err = d->api->FwpmSubLayerAdd0(d->engine, &layer, NULL);
			if (err == ERROR_SUCCESS || err == FWP_E_ALREADY_EXISTS)
			{
				err = this->applyFilters(d->engine);
			}
		}

		// On error undoes any filter-condition applied
		// within our dynamic-session...
		if (err != ERROR_SUCCESS && d->engine)
		{
			d->api->FwpmEngineClose0(d->engine);
			d->engine = NULL;
		}
	}
	else if (d->getAdaptersInfo)
	{
		this->forceStaticDns();
	}
	else
	{
#ifdef Q_UNREACHABLE_X
		Q_UNREACHABLE_X("DnsBlocker.start", "maybe prepare() is not called");
#endif
	}
}

void DnsBlocker::stop()
{
	if (d->api)
	{
		if (d->engine)
		{
			// We undo any filter-condition applied within our dynamic-session
			// by simply closing the session,
			// instead of calling "FwpmFilterDeleteById0(engine, filterId);"
			// for each filter-id then "FwpmSubLayerDeleteByKey0(engine, DnsBlockerGuid);"
			d->api->FwpmEngineClose0(d->engine);
			d->engine = NULL;
		}
	}
	else
	{
		this->useDhcp();
	}
}

bool DnsBlocker::isFilterable() const
{
	return d->api
		&& d->api->FwpmSubLayerAdd0
		&& d->api->FwpmGetAppIdFromFileName0
		&& d->convertInterfaceIndexToLuid;
}

unsigned int DnsBlocker::applyFilters(void *engine)
{
	wchar_t appPath[MAX_PATH];
	FWP_BYTE_BLOB *appBlob = NULL;

	::GetExeNameW(appPath, sizeof(appPath));

	DWORD err = d->api->FwpmGetAppIdFromFileName0(appPath, &appBlob);
	if (err != ERROR_SUCCESS)
	{
		return err;
	}

	// Prepare filter settings
	FWPM_FILTER0 filter = {0};
	UINT64 filterId;
	FWPM_FILTER_CONDITION0 conditions[2] = {0}; // Reserves two filter-conditions

	filter.subLayerKey = DnsBlockerGuid;
	filter.displayData.name = const_cast<wchar_t *>(DNSBLOCKER_LAYER_NAME_W);
	filter.filterCondition = conditions;

	// and the first condition always just specifies that the
	// filter should only apply when remote-port is 53
	conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
	conditions[0].matchType = FWP_MATCH_EQUAL;
	conditions[0].conditionValue.type = FWP_UINT16;
	conditions[0].conditionValue.uint16 = 53;

	// First we prevent any application from using DNS-queries
	// by blocking remote-port 53 (which is specified in above condition)
	filter.numFilterConditions = 1;
	filter.action.type = FWP_ACTION_BLOCK;
	filter.weight.type = FWP_EMPTY; // automatic weighting

	// apply the filter and its condition into the system (first for IPv4)
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	err = d->api->FwpmFilterAdd0(engine, &filter, NULL, &filterId);
	if (err != ERROR_SUCCESS)
	{
		goto posEndFunc;
	}

	// repeat for IPv6
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	err = d->api->FwpmFilterAdd0(engine, &filter, NULL, &filterId);
	if (err != ERROR_SUCCESS)
	{
		goto posEndFunc;
	}

	// Then below allows remote-port 53 (i.e. DNS-queries) to be used from our App
	// hence we set below condition to target our own application only
	conditions[1].fieldKey = FWPM_CONDITION_ALE_APP_ID;
	conditions[1].matchType = FWP_MATCH_EQUAL;
	conditions[1].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	conditions[1].conditionValue.byteBlob = appBlob;

	// config the filter (for both IPv4 and IPv6)
	filter.numFilterConditions = 2;
	filter.action.type = FWP_ACTION_PERMIT;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0xF; // ensures higher priority then above block-filter by using non-zero weight

	// apply for IPv4
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	err = d->api->FwpmFilterAdd0(engine, &filter, NULL, &filterId);
	if (err != ERROR_SUCCESS)
	{
		goto posEndFunc;
	}

	// repeat for IPv6
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	err = d->api->FwpmFilterAdd0(engine, &filter, NULL, &filterId);
	if (err != ERROR_SUCCESS)
	{
		goto posEndFunc;
	}

	// At last we also allow all our network-adapters to use remote-port 53
	// by again modifying the second filter-condition
	conditions[1].fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
	conditions[1].matchType = FWP_MATCH_EQUAL;
	conditions[1].conditionValue.type = FWP_UINT64;
	filter.numFilterConditions = 2;
	filter.action.type = FWP_ACTION_PERMIT;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0xE; // ensures higher priority...

	// iterate through all adapters
	IP_ADAPTER_INFO *adapters = d->getAdapters();
	for (IP_ADAPTER_INFO *a = adapters; a != 0; a = a->Next)
	{
		// Allows only our adapters by checking start of adapter-description
		// the adapter-GUID should be {F3022834-82DA-44D3-8C78-3F6F4D4F52CC}.
		a->Description[sizeof(a->Description) - 1] = 0;
		if (IsSoftEtherAdapter(a->Description) == false)
		{
			continue; // is NOT one of our own adapters
		}

		// convert index to ID for filter-condition
		NET_LUID interfaceId;
		if (d->convertInterfaceIndexToLuid(a->Index, &interfaceId) != NO_ERROR)
		{
			continue; // maybe we should break here, since it could be our adapter
		}

		conditions[1].conditionValue.uint64 = &interfaceId.Value;

		// apply for IPv4
		filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
		err = d->api->FwpmFilterAdd0(engine, &filter, NULL, &filterId);
		if (err != ERROR_SUCCESS)
		{
			break;
		}

		// repeat for IPv6
		filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
		err = d->api->FwpmFilterAdd0(engine, &filter, NULL, &filterId);
		if (err != ERROR_SUCCESS)
		{
			break;
		}
	}

	::free(adapters);

posEndFunc:
	if (appBlob)
	{
		d->api->FwpmFreeMemory0(reinterpret_cast<void **>(&appBlob));
	}

	return err;
}

IP_ADAPTER_INFO *DnsBlockerPrivate::getAdapters() const
{
	IP_ADAPTER_INFO *buffer = NULL;
	ULONG bufferSize = 0;
	DWORD r = 0;

	if (this->getAdaptersInfo == NULL)
	{
		return NULL;
	}

	// retry up to 5 times, to get the adapter infos needed
	for (int i = 0; i < 5; ++i)
	{
		// note: allows fetching required buffer-size by accepting NULL as first argument
		r = this->getAdaptersInfo(buffer, &bufferSize);
		if (r == ERROR_BUFFER_OVERFLOW)
		{
			::free(buffer);
			buffer = static_cast<IP_ADAPTER_INFO *>(::malloc(bufferSize));
		}
		else
		{
			break;
		}
	}

	// at last handle the result
	if (r == NO_ERROR)
	{
		return buffer;
	}

	::free(buffer);
	return NULL;
}

int DnsBlocker::forceStaticDns()
{
	char cmd[1024];
	int count = 0;

	// iterate through all adapters
	IP_ADAPTER_INFO *adapters = d->getAdapters();
	for (IP_ADAPTER_INFO *a = adapters; a != 0; a = a->Next)
	{
		// Excludes our adapters by checking start of adapter-description
		a->Description[sizeof(a->Description) - 1] = 0;
		if (IsSoftEtherAdapter(a->Description))
		{
			continue; // is one of our own adapters
		}

		// apply for IPv4
		sprintf(cmd, "netsh interface ip set dns \"%d\" static 127.0.0.1", a->Index);
		system(cmd);

		// repeat for IPv6
		sprintf(cmd, "netsh interface ipv6 set dns \"%d\" static ::1", a->Index);
		system(cmd);

		++count;
	}

	::free(adapters);
	return count;
}

int DnsBlocker::useDhcp()
{
	char cmd[1024];
	int count = 0;

	// iterate through all adapters
	IP_ADAPTER_INFO *adapters = d->getAdapters();
	for (IP_ADAPTER_INFO *a = adapters; a != 0; a = a->Next)
	{
		// Excludes our adapters by checking start of adapter-description
		a->Description[sizeof(a->Description) - 1] = 0;
		if (IsSoftEtherAdapter(a->Description))
		{
			continue; // is one of our own adapters
		}

		// apply for IPv4
		sprintf(cmd, "netsh interface ip set dns \"%d\" dhcp", a->Index);
		system(cmd);

		// repeat for IPv6
		sprintf(cmd, "netsh interface ipv6 set dns \"%d\" dhcp", a->Index);
		system(cmd);

		++count;
	}

	::free(adapters);
	return count;
}

extern "C" {

void *NewDnsBlocker()
{
	return new DnsBlocker();
}

void FreeDnsBlocker(void *blocker)
{
	delete static_cast<DnsBlocker *>(blocker);
}

void PrepareDnsBlocker(void *blocker)
{
	if (blocker != NULL)
	{
		static_cast<DnsBlocker *>(blocker)->prepare();
	}
}

void StartDnsBlocker(void *blocker)
{
	if (blocker != NULL)
	{
		static_cast<DnsBlocker *>(blocker)->start();
	}
}

void StopDnsBlocker(void *blocker)
{
	if (blocker != NULL)
	{
		static_cast<DnsBlocker *>(blocker)->stop();
	}
}

}

#endif // OS_WIN32
