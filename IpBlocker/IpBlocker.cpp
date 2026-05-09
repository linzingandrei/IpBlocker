#define CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "stdio.h"
#include "ws2tcpip.h"
#include "fwpmu.h"
#include "conio.h"

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Ws2_32.lib")


WCHAR* GetIpsOfWebsite(WCHAR* nodeName)
{
    ADDRINFOW addrInfo = { 0 };
    ADDRINFOW* addrInfoRes = NULL;

    memset(&addrInfo, 0, sizeof(addrInfo));
    addrInfo.ai_family = AF_UNSPEC;
    int ret = GetAddrInfoW(nodeName, NULL, &addrInfo, &addrInfoRes);
    if (ret != 0) {
        printf("GetAddrInfoW failed with error: %d\n", ret);
        FreeAddrInfo(addrInfoRes);
    }
    else 
    {
        WCHAR ipStr[NI_MAXHOST];
        WCHAR* ipStrRes = NULL;
		ipStrRes = (WCHAR*)malloc(NI_MAXHOST * sizeof(WCHAR));

        for (ADDRINFOW* ptr = addrInfoRes; ptr != NULL; ptr = ptr->ai_next) {
            ret = GetNameInfoW(ptr->ai_addr, (socklen_t)ptr->ai_addrlen, ipStr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (ret == 0)
            {
                wprintf(L"IP Address: %ls\n", ipStr);
            }
        }

		wcscpy_s(ipStrRes, NI_MAXHOST, ipStr);

        FreeAddrInfo(addrInfoRes);
        return ipStrRes;
    }
}

int main()
{
    WSAData wsa;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (ret != 0) {
        printf("WSAStartup failed with error: %d\n", ret);
        return 1;
	}

    WCHAR* nodeName = NULL;
	nodeName = (WCHAR*)malloc(1024 * sizeof(WCHAR));
	scanf_s("%ls", nodeName, 1024);

	WCHAR* ipStr = GetIpsOfWebsite(nodeName);
    //free(nodeName);

    WCHAR processName[512] = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

    FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION filterConditions[4] = {0};
    FWP_BYTE_BLOB* pAppId = NULL;
    DWORD error = NULL;
    HANDLE hEngine;

	FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);

    if (processName != NULL)
    {
        error = FwpmGetAppIdFromFileName(processName, &pAppId);
        
        if (error != ERROR_SUCCESS)
        {
            printf("FwpmGetAppIdFromFileName failed with error: %d\n", error);
            free(processName);
            WSACleanup();
            return 1;
		}
    }

    if (pAppId)
    {
        wprintf(L"%.*s", (int)(pAppId->size / sizeof(WCHAR)), (WCHAR*)pAppId->data);
    }

    for (int i = 0; i < 4; i++)
    {
		ZeroMemory(&filterConditions[i], sizeof(FWPM_FILTER_CONDITION));
    }
	filterConditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
	filterConditions[0].matchType = FWP_MATCH_EQUAL;
	filterConditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
	filterConditions[0].conditionValue.byteBlob = pAppId;

	filterConditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	filterConditions[1].matchType = FWP_MATCH_EQUAL;
	filterConditions[1].conditionValue.type = FWP_V4_ADDR_MASK;

    FWP_V4_ADDR_AND_MASK* ipAddrMask = NULL;
    ipAddrMask = (FWP_V4_ADDR_AND_MASK*)malloc(sizeof(FWP_V4_ADDR_AND_MASK));
    RtlZeroMemory(ipAddrMask, sizeof(FWP_V4_ADDR_AND_MASK));
	
    char cIpStr[NI_MAXHOST] = { 0 };
    size_t convertedChars = 0;
    wcstombs_s(&convertedChars, cIpStr, NI_MAXHOST, ipStr, _TRUNCATE);

	ipAddrMask->addr = ntohl(inet_addr(cIpStr));
	ipAddrMask->mask = 0xFFFFFFFF;

	filterConditions[1].conditionValue.v4AddrMask = ipAddrMask;

	ZeroMemory(&filter, sizeof(FWPM_FILTER));
    filter.displayData.name = nodeName;
	filter.displayData.description = NULL;
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 2;
	filter.filterCondition = filterConditions;
	filter.action.type = FWP_ACTION_BLOCK;

	int res = FwpmFilterAdd(hEngine, &filter, NULL, NULL);
    if (res != ERROR_SUCCESS)
    {
        printf("FwpmFilterAdd failed with error: %d\n", res);
        free(nodeName);
        WSACleanup();
        return 1;
	}

    while (true)
    {
        if (_kbhit())
        {
            int c = _getch();

            if (c == 27)
            {
                break;
            }
        }
    }

	FwpmFilterDeleteById(hEngine, filter.filterId);

	FwpmEngineClose(hEngine);

    WSACleanup();

    return 0;
}