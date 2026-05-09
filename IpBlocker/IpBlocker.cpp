#define CRT_SECURE_NO_WARNINGS
#include "stdio.h"
#include "ws2tcpip.h"
#include "fwpmu.h"

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
        for (ADDRINFOW* ptr = addrInfoRes; ptr != NULL; ptr = ptr->ai_next) {
            ret = GetNameInfoW(ptr->ai_addr, (socklen_t)ptr->ai_addrlen, ipStr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (ret == 0)
            {
                wprintf(L"IP Address: %ls\n", ipStr);
            }
        }

        FreeAddrInfo(addrInfoRes);
        return ipStr;
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
    free(nodeName);

    //FwpmFilterAdd();

    WSACleanup();

    return 0;
}