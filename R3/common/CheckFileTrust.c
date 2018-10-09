#include <stdio.h>
#include <Windows.h>
#include <Mscat.h>
#include <SoftPub.h>
#include <WinTrust.h>

#pragma comment(linker,"/DEFAULTLIB:WinTrust.lib")

wchar_t *STR2WSTR(char *pmb)
{
    size_t requiredSize = mbstowcs(NULL, pmb, 0);
    wchar_t *pwc = (wchar_t *)malloc( (requiredSize + 1) * sizeof( wchar_t ));
    mbstowcs( pwc, pmb, requiredSize + 1);
    return pwc;
}

BOOL __stdcall CheckFileTrust( char *lpFileName )
{
    BOOL bRet = FALSE;
    WINTRUST_DATA wd = { 0 };
    WINTRUST_FILE_INFO wfi = { 0 };
    WINTRUST_CATALOG_INFO wci = { 0 };
    CATALOG_INFO ci = { 0 };
    WCHAR *wsz; 
    HCATADMIN hCatAdmin = NULL;
    if ( !CryptCATAdminAcquireContext( &hCatAdmin, NULL, 0 ) )
    {
        return FALSE;
    }
    HANDLE hFile = CreateFileA( lpFileName, GENERIC_READ, FILE_SHARE_READ,NULL, OPEN_EXISTING, 0, NULL );
    if ( INVALID_HANDLE_VALUE == hFile )
    {
        CryptCATAdminReleaseContext( hCatAdmin, 0 );
        return FALSE;
    }
    DWORD dwCnt = 100;
    BYTE byHash[100];
    CryptCATAdminCalcHashFromFileHandle( hFile, &dwCnt, byHash, 0 );
    CloseHandle( hFile );
    LPWSTR pszMemberTag = new WCHAR[dwCnt * 2 + 1];
    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash( hCatAdmin,byHash, dwCnt, 0, NULL );
    wsz=STR2WSTR(lpFileName); //×ª»»char*Îª¿í×Ö·û´®
    if ( NULL == hCatInfo )
    {
        wfi.cbStruct = sizeof( WINTRUST_FILE_INFO );
        wfi.pcwszFilePath =  wsz;
        wfi.hFile = NULL;
        wfi.pgKnownSubject = NULL;
        wd.cbStruct = sizeof( WINTRUST_DATA );
        wd.dwUnionChoice = WTD_CHOICE_FILE;
        wd.pFile = &wfi;
        wd.dwUIChoice = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwStateAction = WTD_STATEACTION_IGNORE;
        wd.dwProvFlags = WTD_SAFER_FLAG;
        wd.hWVTStateData = NULL;
        wd.pwszURLReference = NULL;
    }
    else
    {
        CryptCATCatalogInfoFromContext( hCatInfo, &ci, 0 );
        wci.cbStruct = sizeof( WINTRUST_CATALOG_INFO );
        wci.pcwszCatalogFilePath = ci.wszCatalogFile;
        wci.pcwszMemberFilePath = wsz;
        wci.pcwszMemberTag = pszMemberTag;
        wd.cbStruct = sizeof( WINTRUST_DATA );
        wd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wd.pCatalog = &wci;
        wd.dwUIChoice = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
        wd.dwProvFlags = 0;
        wd.hWVTStateData = NULL;
        wd.pwszURLReference = NULL;
    }
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    HRESULT hr = WinVerifyTrust( NULL, &action, &wd );
    bRet = SUCCEEDED( hr );
    if ( NULL != hCatInfo )
    {
        CryptCATAdminReleaseCatalogContext( hCatAdmin, hCatInfo, 0 );
    }
    CryptCATAdminReleaseContext( hCatAdmin, 0 );
    delete[] pszMemberTag;
    return bRet;
}

int main()
{
        char xxx[260]={0};
yyy:
        printf("input filename: ");
        scanf("%s",xxx);
        printf("%ld\n",CheckFileTrust(xxx));        
        getchar();
        getchar();
        goto yyy;
        return 0;
}