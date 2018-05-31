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





//LAST

#LAST

#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "IPHLPAPI.lib")
#include <conio.h>
// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")
#include <iostream>
#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "123"
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
using namespace std;
char *message;
IP_ADAPTER_INFO  *pAdapterInfo;
ULONG            ulOutBufLen;
DWORD            dwRetVal;
void printIP(char String[4 * 4]) {
	if (strcmp(String, "0.0.0.0") == 0) {
		cout << endl;
	}
	else {
		cout << String << endl;
	}
}
char* call_ip_config() {

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) != ERROR_SUCCESS) {
		printf("GetAdaptersInfo call failed with %d\n", dwRetVal);
		return NULL;
	}
	else {
		string msg = "";
		char sendMsg[1024];
		PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
		printf("Windows IP Configuration\n\n\n");
		strncpy(sendMsg, "Windows IP Configuration\n\n\n", sizeof(sendMsg));
		while (pAdapter) {
			switch (pAdapter->Type) {
			case MIB_IF_TYPE_OTHER:
				printf("Other ");
				strncat(sendMsg, "Other ", (sizeof(sendMsg) - strlen(sendMsg)));
				break;
			case MIB_IF_TYPE_ETHERNET:
				printf("Ethernet ");
				strncat(sendMsg, "Ethernet ", (sizeof(sendMsg) - strlen(sendMsg)));
				break;
			case MIB_IF_TYPE_TOKENRING:
				printf("Token Ring ");
				msg += "Token Ring ";
				strncat(sendMsg, "Token Ring ", (sizeof(sendMsg) - strlen(sendMsg)));
				break;
			case MIB_IF_TYPE_FDDI:
				printf("FDDI ");
				msg += "FDDI ";
				break;
			case MIB_IF_TYPE_PPP:
				printf("PPP ");
				msg += "PPP ";
				break;
			case MIB_IF_TYPE_LOOPBACK:
				printf("Lookback ");
				msg += "Lookback ";
				break;
			case MIB_IF_TYPE_SLIP:
				printf("Slip ");
				msg += "Slip ";
				break;
			default:
				printf("");
				break;
			}
			printf("%s\n\n", pAdapter->Description);
			strncat(sendMsg, pAdapter->Description, (sizeof(sendMsg) - strlen(sendMsg)));
			strncat(sendMsg, "\n\n", (sizeof(sendMsg) - strlen(sendMsg)));
			printf("\tConnection-specific DNS Suffix  . : ");

			strncat(sendMsg, "\tConnection-specific DNS Suffix  . : ", (sizeof(sendMsg) - strlen(sendMsg)));
			strncat(sendMsg, pAdapter->DhcpServer.IpAddress.String, (sizeof(sendMsg) - strlen(sendMsg)));
			strncat(sendMsg, "\n", (sizeof(sendMsg) - strlen(sendMsg)));

			printIP(pAdapter->DhcpServer.IpAddress.String);
			printf("\tIPv4 Address. . . . . . . . . . . : ");
			strncat(sendMsg, "\tIPv4 Address. . . . . . . . . . . : ", (sizeof(sendMsg) - strlen(sendMsg)));
			strncat(sendMsg, pAdapter->DhcpServer.IpAddress.String, (sizeof(sendMsg) - strlen(sendMsg)));
			strncat(sendMsg, "\n", (sizeof(sendMsg) - strlen(sendMsg)));

			printIP(pAdapter->IpAddressList.IpAddress.String);
			printf("\tSubnet Mask . . . . . . . . . . . : ");
			strncat(sendMsg, "\tSubnet Mask . . . . . . . . . . . : ", (sizeof(sendMsg) - strlen(sendMsg)));
			strncat(sendMsg, pAdapter->IpAddressList.IpAddress.String, (sizeof(sendMsg) - strlen(sendMsg)));
			strncat(sendMsg, "\n", (sizeof(sendMsg) - strlen(sendMsg)));
			printIP(pAdapter->DhcpServer.IpMask.String);


			printf("\tDefault Gateway . . . . . . . . . : ");
			strncat(sendMsg, "\tDefault Gateway . . . . . . . . . : ", (sizeof(sendMsg) - strlen(sendMsg)));
			strncat(sendMsg, pAdapter->GatewayList.IpAddress.String, (sizeof(sendMsg) - strlen(sendMsg)));
			strncat(sendMsg, "\n\n", (sizeof(sendMsg) - strlen(sendMsg)));
			printIP(pAdapter->GatewayList.IpAddress.String);
			cout << endl << endl;
			pAdapter = pAdapter->Next;
		}
		return sendMsg;
	}
}
char * call_renew() {
	ULONG ulOutBufLen = 0;
	DWORD dwRetVal = 0;
	PIP_INTERFACE_INFO pInfo;
	char sendMsg[1024];
	pInfo = (IP_INTERFACE_INFO *)MALLOC(sizeof(IP_INTERFACE_INFO));

	// Make an initial call to GetInterfaceInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetInterfaceInfo(pInfo, &ulOutBufLen) == ERROR_INSUFFICIENT_BUFFER) {
		FREE(pInfo);
		pInfo = (IP_INTERFACE_INFO *)MALLOC(ulOutBufLen);
	}

	// Make a second call to GetInterfaceInfo to get the
	// actual data we want
	if ((dwRetVal = GetInterfaceInfo(pInfo, &ulOutBufLen)) == NO_ERROR) {
		//printf("\tAdapter Name: %ws\n", pInfo->Adapter[0].Name);
		//printf("\tAdapter Index: %ld\n", pInfo->Adapter[0].Index);
		//printf("\tNum Adapters: %ld\n", pInfo->NumAdapters);
		printf("\nCall ipconfig /renew...\n");
		strncpy(sendMsg, "\nCall ipconfig /renew...\n", sizeof(sendMsg));
	}
	else if (dwRetVal == ERROR_NO_DATA) {
		printf("There are no network adapters with IPv4 enabled on the local system\n");
		strncpy(sendMsg, "There are no network adapters with IPv4 enabled on the local system\n", sizeof(sendMsg));
		return sendMsg;
	}
	else {
		LPVOID lpMsgBuf;
		strncpy(sendMsg, "GetInterfaceInfo failed.\n", sizeof(sendMsg));
		return sendMsg;
		printf("GetInterfaceInfo failed.\n");

		if (FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dwRetVal,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			(LPTSTR)&lpMsgBuf,
			0,
			NULL)) {
			printf("\tError: %s", lpMsgBuf);
		}
		LocalFree(lpMsgBuf);
		return NULL;
	}

	// Call IpReleaseAddress and IpRenewAddress to release and renew
	// the IP address on the first network adapter returned 
	// by the call to GetInterfaceInfo.
	PIP_INTERFACE_INFO pAdapter = pInfo;
	int isSucces = 0;
	for (int i = 0; i < pAdapter->NumAdapters; i++) {
		/*if ((dwRetVal = IpReleaseAddress(&pInfo->Adapter[i])) == NO_ERROR) {
		printf("IP release succeeded.\n");
		}
		else {
		printf("IP release failed: %ld\n", dwRetVal);
		}*/

		if ((dwRetVal = IpRenewAddress(&pInfo->Adapter[i])) == NO_ERROR) {
			isSucces = 1;
		}
		else {
			//printf("IP renew failed: %ld\n", dwRetVal);
		}
	}
	call_ip_config();
	if (isSucces == 1) {
		strncat(sendMsg, "\n\nipconfig /renew succeeded.\n", (sizeof(sendMsg) - strlen(sendMsg)));
		printf("\n\nipconfig /renew succeeded.\n");
	}
	else {
		strncat(sendMsg, "\n\nipconfig /renew failed.\n", (sizeof(sendMsg) - strlen(sendMsg)));
		printf("\n\nipconfig /renew failed.\n");
	}
	if (pInfo != NULL) {
		FREE(pInfo);
	}
	return sendMsg;
}
char * show_info() {
	char sendMsg[1024];
	strncpy(sendMsg, "\n>ipconfig         ...Show information\n>ipconfig /renew  ...Renew all adapters\n>ipconfig /release...release all matching conections\n", sizeof(sendMsg));
	return sendMsg;
}
char * call_release() {
	char sendMsg[1024];
	ULONG ulOutBufLen = 0;
	DWORD dwRetVal = 0;
	PIP_INTERFACE_INFO pInfo;
	pInfo = (IP_INTERFACE_INFO *)MALLOC(sizeof(IP_INTERFACE_INFO));

	// Make an initial call to GetInterfaceInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetInterfaceInfo(pInfo, &ulOutBufLen) == ERROR_INSUFFICIENT_BUFFER) {
		FREE(pInfo);
		pInfo = (IP_INTERFACE_INFO *)MALLOC(ulOutBufLen);
	}

	// Make a second call to GetInterfaceInfo to get the
	// actual data we want
	if ((dwRetVal = GetInterfaceInfo(pInfo, &ulOutBufLen)) == NO_ERROR) {
		//printf("\tAdapter Name: %ws\n", pInfo->Adapter[0].Name);
		//printf("\tAdapter Index: %ld\n", pInfo->Adapter[0].Index);
		//printf("\tNum Adapters: %ld\n", pInfo->NumAdapters);
		printf("\nCall ipconfig /release...\n");
		strncpy(sendMsg, "\nCall ipconfig /release...\n", sizeof(sendMsg));
	}
	else if (dwRetVal == ERROR_NO_DATA) {
		printf("There are no network adapters with IPv4 enabled on the local system\n");
		strncpy(sendMsg, "There are no network adapters with IPv4 enabled on the local system\n", sizeof(sendMsg));
		return sendMsg;
	}
	else {
		LPVOID lpMsgBuf;
		printf("GetInterfaceInfo failed.\n");
		strncpy(sendMsg, "GetInterfaceInfo failed.\n", sizeof(sendMsg));
		return sendMsg;
		if (FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dwRetVal,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			(LPTSTR)&lpMsgBuf,
			0,
			NULL)) {
			printf("\tError: %s", lpMsgBuf);
		}
		LocalFree(lpMsgBuf);
		return NULL;
	}

	// Call IpReleaseAddress and IpRenewAddress to release and renew
	// the IP address on the first network adapter returned 
	// by the call to GetInterfaceInfo.
	PIP_INTERFACE_INFO pAdapter = pInfo;
	int isSucces = 0;
	for (int i = 0; i < pAdapter->NumAdapters; i++) {
		if ((dwRetVal = IpReleaseAddress(&pInfo->Adapter[i])) == NO_ERROR) {
			isSucces = 1;
		}
		else {
		}
	}
	call_ip_config();
	if (isSucces == 1) {
		printf("\n\nipconfig /release succeeded.\n");
		strncat(sendMsg, "\n\nipconfig /release succeeded.\n", (sizeof(sendMsg) - strlen(sendMsg)));
	}
	else {
		printf("\n\nipconfig /release failed.\n");
		strncat(sendMsg, "\n\nipconfig /release failed.\n", (sizeof(sendMsg) - strlen(sendMsg)));
	}
	if (pInfo != NULL) {
		FREE(pInfo);
	}
	return sendMsg;
}
int __cdecl main(void)
{
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
	}
	WSADATA wsaData;
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iSendResult;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	while (true)
	{
		iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) {
			printf("WSAStartup failed with error: %d\n", iResult);
			return 1;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;

		// Resolve the server address and port
		iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
		if (iResult != 0) {
			printf("getaddrinfo failed with error: %d\n", iResult);
			WSACleanup();
			return 1;
		}

		// Create a SOCKET for connecting to server
		ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
		if (ListenSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			freeaddrinfo(result);
			WSACleanup();
			return 1;
		}

		// Setup the TCP listening socket
		iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			printf("bind failed with error: %d\n", WSAGetLastError());
			freeaddrinfo(result);
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}

		freeaddrinfo(result);

		iResult = listen(ListenSocket, SOMAXCONN);
		if (iResult == SOCKET_ERROR) {
			printf("listen failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}

		// Accept a client socket
		ClientSocket = accept(ListenSocket, NULL, NULL);
		if (ClientSocket == INVALID_SOCKET) {
			printf("accept failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}

		// No longer need server socket
		closesocket(ListenSocket);

		// Receive until the peer shuts down the connection
		do {
			iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
			if (iResult > 0) {
				printf("Bytes received: %d\n", iResult);
				if (recvbuf[0] == '0') {
					printf("Client : ipconfig\n\n");
					char *returned_str = call_ip_config();
					iSendResult = send(ClientSocket, returned_str, strlen(returned_str), 0);
				}
				else if (recvbuf[0] == '1') {
					printf("Client : ipconfig /renew\n\n");
					char *returned_str = call_renew();
					iSendResult = send(ClientSocket, returned_str, strlen(returned_str), 0);
				}
				else if (recvbuf[0] == '2') {
					printf("Client : ipconfig /release\n\n");
					char *returned_str = call_release();
					iSendResult = send(ClientSocket, returned_str, strlen(returned_str), 0);
				}
				else {
					printf("Client : ipconfig ?\n\n");
					char *returned_str = show_info();
					iSendResult = send(ClientSocket, returned_str, strlen(returned_str), 0);
				}
				char* messageBuf = (char*)malloc(sizeof(char) * 1025);
				messageBuf[0] = '?';
				messageBuf[1] = '\0';
				
				printf("Da gui: \n");
			}
			else if (iResult == 0) {

			}
				//printf("Connection closing...\n");
			else {
				printf("recv failed with error: %d\n", WSAGetLastError());
				closesocket(ClientSocket);
				WSACleanup();
				return 1;
			}

		} while (iResult > 0);

		// shutdown the connection since we're done
		iResult = shutdown(ClientSocket, SD_SEND);
		if (iResult == SOCKET_ERROR) {
			printf("shutdown failed with error: %d\n", WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}

		// cleanup
		closesocket(ClientSocket);
		WSACleanup();
	}
	
	getchar();
	return 0;
}

//CLIENT
#CLIENT
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.TextArea;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;

public class Client {
  static String serverAddress;
  static int serverPort;
  static Socket socket;
  static DataInputStream inStream;
  static DataOutputStream outStream;
  static JFrame splashFrame, frame;
  JPanel outputPanel, inputPanel;
  private JPanel contentPane;
  private JTextField input;
  TextArea output;

  public Client() {
    initGUI();
    addListeners();
  }

  private void initGUI() {
    frame = new JFrame("Ch\u01B0\u01A1ng tr\u00ECnh t\u1EA1i Client " 
 							+ serverAddress + ":" + serverPort);
    frame.setLayout(new GridLayout(2, 1));
    frame.setBounds(200, 200, 500, 200);
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setBounds(100, 100, 427, 300);
	contentPane = new JPanel();
	contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
	frame.setContentPane(contentPane);
	contentPane.setLayout(null);
	
	JLabel lblRequest = new JLabel("Request");
	lblRequest.setBounds(10, 11, 414, 14);
	contentPane.add(lblRequest);
	
	input = new JTextField();
	input.setBounds(10, 36, 188, 20);
	contentPane.add(input);
	input.setColumns(10);
	JButton btnSend = new JButton("Send");
	btnSend.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent arg0) {
			String expresion = input.getText();
			output.append("Request = " + (expresion.isEmpty() ? "null" : expresion )+ "\n");
	        try {
	          socket = new Socket(serverAddress, serverPort);
	          socket.setSoTimeout(1000);
	          inStream = new DataInputStream(socket.getInputStream());
	          outStream = new DataOutputStream(socket.getOutputStream());
	          if (expresion.equals("ipconfig")) {
	        	  expresion = "0";
	          }else if (expresion.equals("ipconfig /renew")) {
	        	  expresion = "1";
	          }else if (expresion.equals("ipconfig /release")) {
	        	  expresion = "2";
	          }else {
	        	  expresion = "3";
	          }
	          outStream.write(expresion.trim().getBytes());
	          
	          byte[] bytes = new byte[1025];
              String data;
              inStream.read(bytes);
              data = bytes.toString();
              
	          String result = new String(bytes);
	          output.append("Result = " +result + "\n");
	          inStream.close();
	          outStream.close();
	          socket.close();
	        } catch (UnknownHostException e) {
	          JOptionPane.showMessageDialog(null, "Không tìm thấy Server.");
	          e.printStackTrace();
	        } catch (IOException e) {
	          JOptionPane.showMessageDialog(null, "Lỗi kết nối vào ra khi truyền dữ liệu.");
	          e.printStackTrace();
	        }
		}
	});
	btnSend.setBounds(212, 36, 89, 23);
	contentPane.add(btnSend);
	
	JButton btnClean = new JButton("Clean");
	btnClean.addActionListener(new ActionListener() {
		@Override
		public void actionPerformed(ActionEvent e) {
			input.setText("");
		}
	});
	btnClean.setBounds(311, 36, 89, 23);
	contentPane.add(btnClean);
	
	JLabel lblResponse = new JLabel("Response");
	lblResponse.setBounds(10, 67, 390, 14);
	contentPane.add(lblResponse);
	
	output = new TextArea();
	output.setBounds(10, 92, 390, 158);
	contentPane.add(output);
	
	output.setEditable(false);
    frame.setVisible(true);
  }

  private void addListeners() {
    frame.addWindowListener(new WindowListener() {
      @Override
      public void windowOpened(WindowEvent arg0) {
        splashFrame.setVisible(false);
      }
      @Override
      public void windowIconified(WindowEvent arg0) {}
      @Override
      public void windowDeiconified(WindowEvent arg0) {}
      @Override
      public void windowDeactivated(WindowEvent arg0) {}
      @Override
      public void windowClosing(WindowEvent arg0) {}
      @Override
      public void windowClosed(WindowEvent arg0) {
        splashFrame.setVisible(true);
        frame.setVisible(false);
      }
      @Override
      public void windowActivated(WindowEvent arg0) {}
    });
  }

  /**
   * @param args
   */
  public static void main(String[] args) {
    splashFrame = new JFrame("Nhập thông tin");
    splashFrame.setBounds(200, 200,300, 100);
    splashFrame.setResizable(false);
    splashFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    splashFrame.setLayout(new BorderLayout());
    splashFrame.add(new JLabel("Nhập địa chỉ máy chủ và cổng"), BorderLayout.NORTH);
    JTextField host, port;
    host = new JTextField("Localhost");
    port = new JTextField("123");
    splashFrame.add(host, BorderLayout.CENTER);
    splashFrame.add(port, BorderLayout.EAST);
    JButton enterBtn = new JButton("Enter");
    splashFrame.add(enterBtn, BorderLayout.SOUTH);
    splashFrame.setVisible(true);
    enterBtn.addActionListener(new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent arg0) {
        serverAddress = host.getText();
        serverPort = Integer.parseInt(port.getText());
        new Client();
      }
    });
  }
}
