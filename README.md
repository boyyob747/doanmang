# doanmang
// DoAnMang.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "IPHLPAPI.lib")
#include <conio.h>
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

/* Note: could also use malloc() and free() */

int __cdecl main()
{

	/* Declare and initialize variables */

	// It is possible for an adapter to have multiple
	// IPv4 addresses, gateways, and secondary WINS servers
	// assigned to the adapter. 
	//
	// Note that this sample code only prints out the 
	// first entry for the IP address/mask, and gateway, and
	// the primary and secondary WINS server for each adapter. 

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	/* variables used to print DHCP time info */
	struct tm newtime;
	char buffer[32];
	errno_t error;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			printf("\tComboIndex: \t%d\n", pAdapter->ComboIndex);
			printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
			printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
			printf("\tAdapter Addr: \t");
			for (i = 0; i < pAdapter->AddressLength; i++) {
				if (i == (pAdapter->AddressLength - 1))
					printf("%.2X\n", (int)pAdapter->Address[i]);
				else
					printf("%.2X-", (int)pAdapter->Address[i]);
			}
			printf("\tIndex: \t%d\n", pAdapter->Index);
			printf("\tType: \t");
			switch (pAdapter->Type) {
			case MIB_IF_TYPE_OTHER:
				printf("Other\n");
				break;
			case MIB_IF_TYPE_ETHERNET:
				printf("Ethernet\n");
				break;
			case MIB_IF_TYPE_TOKENRING:
				printf("Token Ring\n");
				break;
			case MIB_IF_TYPE_FDDI:
				printf("FDDI\n");
				break;
			case MIB_IF_TYPE_PPP:
				printf("PPP\n");
				break;
			case MIB_IF_TYPE_LOOPBACK:
				printf("Lookback\n");
				break;
			case MIB_IF_TYPE_SLIP:
				printf("Slip\n");
				break;
			default:
				printf("Unknown type %ld\n", pAdapter->Type);
				break;
			}

			printf("\tIP Address: \t%s\n",
				pAdapter->IpAddressList.IpAddress.String);
			printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);

			printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
			printf("\t***\n");

			if (pAdapter->DhcpEnabled) {
				printf("\tDHCP Enabled: Yes\n");
				printf("\t  DHCP Server: \t%s\n",
					pAdapter->DhcpServer.IpAddress.String);

				printf("\t  Lease Obtained: ");
				/* Display local time */
				error = _localtime32_s(&newtime, (__time32_t*)&pAdapter->LeaseObtained);
				if (error)
					printf("Invalid Argument to _localtime32_s\n");
				else {
					// Convert to an ASCII representation 
					error = asctime_s(buffer, 32, &newtime);
					if (error)
						printf("Invalid Argument to asctime_s\n");
					else
						/* asctime_s returns the string terminated by \n\0 */
						printf("%s", buffer);
				}

				printf("\t  Lease Expires:  ");
				error = _localtime32_s(&newtime, (__time32_t*)&pAdapter->LeaseExpires);
				if (error)
					printf("Invalid Argument to _localtime32_s\n");
				else {
					// Convert to an ASCII representation 
					error = asctime_s(buffer, 32, &newtime);
					if (error)
						printf("Invalid Argument to asctime_s\n");
					else
						/* asctime_s returns the string terminated by \n\0 */
						printf("%s", buffer);
				}
			}
			else
				printf("\tDHCP Enabled: No\n");

			if (pAdapter->HaveWins) {
				printf("\tHave Wins: Yes\n");
				printf("\t  Primary Wins Server:    %s\n",
					pAdapter->PrimaryWinsServer.IpAddress.String);
				printf("\t  Secondary Wins Server:  %s\n",
					pAdapter->SecondaryWinsServer.IpAddress.String);
			}
			else
				printf("\tHave Wins: No\n");
			pAdapter = pAdapter->Next;
			printf("\n");
		}
	}
	else {
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);

	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);

	getchar();
}

#//2
// DoAnMang.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "IPHLPAPI.lib")
#include <conio.h>
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

/* Note: could also use malloc() and free() */
IP_ADAPTER_INFO  *pAdapterInfo;
ULONG            ulOutBufLen;
DWORD            dwRetVal;
int main() 
{
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
	}
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) != ERROR_SUCCESS) {
		printf("GetAdaptersInfo call failed with %d\n", dwRetVal);
	}
	else {
		PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
		printf("Windows IP Configuration\n\n\n");
		while (pAdapter) {
			//printf("Adapter Name: %s\n", pAdapter->AdapterName);
			printf("%s\n\n", pAdapter->Description);
			printf("\tAdapter Addr: \t");
			for (UINT i = 0; i < pAdapter->AddressLength; i++) {
				if (i == (pAdapter->AddressLength - 1))
					printf("%.2X\n", (int)pAdapter->Address[i]);
				else
					printf("%.2X-", (int)pAdapter->Address[i]);
			}
			printf("\tIPv4 Address. . . . . . . . . . . : %s\n", pAdapter->IpAddressList.IpAddress.String);
			printf("\tSubnet Mask . . . . . . . . . . . : %s\n", pAdapter->IpAddressList.IpMask.String);
			printf("\tDefault Gateway . . . . . . . . . : %s\n\n", pAdapter->GatewayList.IpAddress.String);
			/*if (pAdapter->DhcpEnabled) {
				printf("\tDHCP Enabled: Yes\n");
				printf("\t\tDHCP Server: \t%s\n", pAdapter->DhcpServer.IpAddress.String);
			}
			else
				printf("\tDHCP Enabled: No\n");*/
			

			pAdapter = pAdapter->Next;
		}
	}

	getchar();
}


//ip 6
#include "stdafx.h"
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <stdio.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

void print_adapter(PIP_ADAPTER_ADDRESSES aa)
{
	char buf[BUFSIZ];
	memset(buf, 0, BUFSIZ);
	WideCharToMultiByte(CP_ACP, 0, aa->FriendlyName, wcslen(aa->FriendlyName), buf, BUFSIZ, NULL, NULL);
	printf("adapter_name:%s\n", buf);
}

void print_addr(PIP_ADAPTER_UNICAST_ADDRESS ua)
{
	char buf[BUFSIZ];

	int family = ua->Address.lpSockaddr->sa_family;
	printf("\t%s ", family == AF_INET ? "IPv4" : "IPv6");

	memset(buf, 0, BUFSIZ);
	getnameinfo(ua->Address.lpSockaddr, ua->Address.iSockaddrLength, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
	printf("%s\n", buf);
}

bool print_ipaddress()
{
	DWORD rv, size;
	PIP_ADAPTER_ADDRESSES adapter_addresses, aa;
	PIP_ADAPTER_UNICAST_ADDRESS ua;

	rv = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size);
	if (rv != ERROR_BUFFER_OVERFLOW) {
		fprintf(stderr, "GetAdaptersAddresses() failed...");
		return false;
	}
	adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);

	rv = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &size);
	if (rv != ERROR_SUCCESS) {
		fprintf(stderr, "GetAdaptersAddresses() failed...");
		free(adapter_addresses);
		return false;
	}

	for (aa = adapter_addresses; aa != NULL; aa = aa->Next) {
		print_adapter(aa);
		for (ua = aa->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
			print_addr(ua);
		}
	}

	free(adapter_addresses);
}

int main(int argc, char *argv[])
{
	WSAData d;
	if (WSAStartup(MAKEWORD(2, 2), &d) != 0) {
		return -1;
	}

	print_ipaddress();

	WSACleanup();
	getchar();
	return 0;
}
//new ip 6
#include "stdafx.h"
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <stdio.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iostream>
using namespace std;
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
IP_ADAPTER_INFO  *pAdapterInfo;
ULONG            ulOutBufLen;
DWORD            dwRetVal;

void print_adapter(PIP_ADAPTER_ADDRESSES aa)
{
	char buf[BUFSIZ];
	memset(buf, 0, BUFSIZ);
	WideCharToMultiByte(CP_ACP, 0, aa->FriendlyName, wcslen(aa->FriendlyName), buf, BUFSIZ, NULL, NULL);
	printf("%s :\n\n", buf);
	/*
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS) {
	free(pAdapterInfo);
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
	}
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) != ERROR_SUCCESS) {
	printf("GetAdaptersInfo call failed with %d\n", dwRetVal);
	}
	PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
	while (pAdapter) {
	if (pAdapter->AdapterName == aa->AdapterName) {
	printf("%s\n\n", pAdapter->Description);
	printf("\tAdapter Addr: \t");
	for (UINT i = 0; i < pAdapter->AddressLength; i++) {
	if (i == (pAdapter->AddressLength - 1))
	printf("%.2X\n", (int)pAdapter->Address[i]);
	else
	printf("%.2X-", (int)pAdapter->Address[i]);
	}
	printf("\tIPv4 Address. . . . . . . . . . . : %s\n", pAdapter->IpAddressList.IpAddress.String);
	printf("\tSubnet Mask . . . . . . . . . . . : %s\n", pAdapter->IpAddressList.IpMask.String);
	printf("\tDefault Gateway . . . . . . . . . : %s\n\n", pAdapter->GatewayList.IpAddress.String);
	}
	pAdapter = pAdapter->Next;
	}
	*/
	
}

void print_addr(PIP_ADAPTER_UNICAST_ADDRESS ua)
{
	char buf[BUFSIZ];

	int family = ua->Address.lpSockaddr->sa_family;
	printf("\t%s ", family == AF_INET ? "IPv4 Address. . . . . . . . . . . : " : "Link-local IPv6 Address . . . . . : ");

	memset(buf, 0, BUFSIZ);
	getnameinfo(ua->Address.lpSockaddr, ua->Address.iSockaddrLength, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
	printf("%s\n", buf);
}
bool print_ipaddress()
{
	DWORD rv, size;
	PIP_ADAPTER_ADDRESSES adapter_addresses, aa;
	PIP_ADAPTER_UNICAST_ADDRESS ua;

	rv = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size);
	if (rv != ERROR_BUFFER_OVERFLOW) {
		fprintf(stderr, "GetAdaptersAddresses() failed...");
		return false;
	}
	adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);

	rv = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &size);
	if (rv != ERROR_SUCCESS) {
		fprintf(stderr, "GetAdaptersAddresses() failed...");
		free(adapter_addresses);
		return false;
	}
	printf("\nWindows IP Configuration\n\n");


	for (aa = adapter_addresses; aa != NULL; aa = aa->Next) {
		print_adapter(aa);
		for (ua = aa->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
			print_addr(ua);
		}
	}

	free(adapter_addresses);
}

int main(int argc, char *argv[])
{
	WSAData d;
	if (WSAStartup(MAKEWORD(2, 2), &d) != 0) {
		return -1;
	}

	print_ipaddress();

	WSACleanup();
	getchar();
	return 0;
}
