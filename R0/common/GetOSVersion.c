#include "common.h"

ULONG g_ulOsVersion = OS_VERSION_ERROR;

ULONG GetOSVersion()
{

	RTL_OSVERSIONINFOW osVersionInfo;
	ULONG ulOsVersion;
	ULONG majorVersion;
	ULONG minorVersion;
	ULONG buildNumber;

	PAGED_CODE();

	osVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	if (!NT_SUCCESS(RtlGetVersion(&osVersionInfo))) {
		return OS_VERSION_ERROR;
	}

	majorVersion = osVersionInfo.dwMajorVersion;
	minorVersion = osVersionInfo.dwMinorVersion;
	buildNumber = osVersionInfo.dwBuildNumber;

	if ((majorVersion == 5 && minorVersion == 1) || buildNumber == 2600) {
		g_ulOsVersion = OS_VERSION_XP;
	}
	else if (buildNumber == 2195) {
		g_ulOsVersion = OS_VERSION_2000;
	}
	else if (buildNumber == 3790) {
		g_ulOsVersion = OS_VERSION_SERVER_2003;
	}
	else if (buildNumber == 6000) {
		g_ulOsVersion = OS_VERSION_VISTA;
	}
	else if (buildNumber == 6001) {
		g_ulOsVersion = OS_VERSION_VISTA_SP1;
	}
	else if (buildNumber == 6002) {
		g_ulOsVersion = OS_VERSION_VISTA_SP2;
	}
	else if ((majorVersion == 6 && minorVersion == 1) || buildNumber == 7600) {
		g_ulOsVersion = OS_VERSION_WIN7;
	}
	else if (majorVersion == 6 && minorVersion == 1 && buildNumber == 7601) {
		g_ulOsVersion = OS_VERSION_WIN7_SP1;
	}
	else if ((majorVersion == 6 && minorVersion == 2) || buildNumber == 9200) {
		g_ulOsVersion = OS_VERSION_WIN8;
	}
	else if ((majorVersion == 6 && minorVersion == 3) || buildNumber == 9600) {
		g_ulOsVersion = OS_VERSION_WIN81;
	}
	else if (majorVersion == 10 && minorVersion == 0 && buildNumber == 10240) {
		g_ulOsVersion = OS_VERSION_WIN10240;
	}
	else if (majorVersion == 10 && minorVersion == 0 && buildNumber == 10586) {
		g_ulOsVersion = OS_VERSION_WIN10586;
	}
	else if (majorVersion == 10 && minorVersion == 0 && buildNumber == 14393) {
		g_ulOsVersion = OS_VERSION_WIN14393;
	}
	else if (majorVersion == 10 && minorVersion == 0) {
		g_ulOsVersion = OS_VERSION_WIN10;
	}
	else {
		g_ulOsVersion = OS_VERSION_ERROR;
	}
	ulOsVersion = g_ulOsVersion;
	return g_ulOsVersion;
}