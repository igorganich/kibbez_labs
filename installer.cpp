#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include "Shlwapi.h"
#include <WinDef.h>
#include <wincrypt.h>
#include <tchar.h>
#include <dirent.h>
#include <Lmcons.h>

using namespace std;

static long int		ft_abs(size_t nbr)
{
	return ((nbr < 0) ? -nbr : nbr);
}

static int				ft_len(size_t nbr)
{
	int		len;

	len = (nbr <= 0) ? 1 : 0;
	while (nbr != 0)
	{
		nbr = nbr / 10;
		len++;
	}
	return (len);
}

char			*ft_itoa(size_t nbr)
{
	int			len;
	int			sign;
	char		*c;

	sign = (nbr < 0) ? -1 : 1;
	len = ft_len(nbr);
	c = (char *)malloc(sizeof(char) * len + 1);
	c[len] = '\0';
	len--;
	while (len >= 0)
	{
		c[len] = '0' + ft_abs(nbr % 10);
		nbr = ft_abs(nbr / 10);
		len--;
	}
	if (sign == -1)
		c[0] = '-';
	return (c);
}

char *custom_strcat(const char *first, const char *second)
{
	int size1 = strlen(first);
	int size2 =strlen(second);
	int size = size1 + size2 + 1;
	char *ret = (char*)malloc(size);
	ret[size - 1] = 0;
	int i = 0;
	for (; first[i] != 0; i++)
		ret[i] = first[i];
	for (int l = 0; second[l] != 0; l++)
		ret[i + l] = second[l];
	return (ret);
}

void install_here(const char *path)
{
	ofstream first;
	const char *path3 = "/myprog.exe";
	char *path2 = custom_strcat(path, path3);
	first.open(path2, ios::binary);
	const char *prog = "./2_lab";
	std::ifstream is ("./2_lab.exe", std::ifstream::binary);
	is.seekg (0, is.end);
    int length = is.tellg();
    is.seekg (0, is.beg);
	char * buffer2 = new char [length];
	std::cout << "Reading " << length << " characters... ";
    // read data as a block:
    is.read (buffer2,length);
    cout << buffer2 << endl;
    first.write(buffer2, length);
    path2 = custom_strcat(path, "/users");
    CreateDirectory(path2, NULL);
    first.close();
    is.close();
    first.open(custom_strcat(path2, "/ADMIN"), ios::binary);
    if (first != NULL)
    {
    	buffer2 = "ADMIN\n0\n\n0\n0\n1";
    	first.write(buffer2, strlen(buffer2));
	}
    	// get data from PC
	char *cmp = (char*)calloc(500, 1);
	char *buffer = (char*)calloc(500, 1);
	DWORD len = UNLEN+1;
	GetUserName(buffer, &len);
	strcat(cmp, buffer);
	len = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerName(buffer, &len);
	strcat(cmp, buffer);
	GetWindowsDirectory(buffer, MAX_PATH);
	strcat(cmp, buffer);
	GetSystemDirectory(buffer, MAX_PATH);
	strcat(cmp, buffer);
	int buttons = GetSystemMetrics(SM_CMOUSEBUTTONS);
	itoa(buttons, buffer, 10);
	strcat(cmp, buffer);
	buttons = GetSystemMetrics(SM_CXSCREEN);
	itoa(buttons, buffer, 10);
	strcat(cmp, buffer);
	MEMORYSTATUS stat;
	GlobalMemoryStatus (&stat);
	buffer = ft_itoa(stat.dwTotalPhys);
	strcat(cmp, buffer);
	TCHAR szVolumeName[100]    = "";
	TCHAR szFileSystemName[10] = "";
	DWORD dwSerialNumber       = 0;
	DWORD dwMaxFileNameLength  = 0;
	DWORD dwFileSystemFlags    = 0;
	
	if(::GetVolumeInformation("c:\\",
	                            szVolumeName,
	                            sizeof(szVolumeName),
	                            &dwSerialNumber,
	                            &dwMaxFileNameLength,
	                            &dwFileSystemFlags,
	                            szFileSystemName,
	                            sizeof(szFileSystemName)) == TRUE)
	  {
	  }
	strcat(cmp, szFileSystemName);
	cout << cmp << endl;
	// GET HASH OF DATA
		
	HCRYPTPROV hProv;
	DWORD      dwKeySpec = AT_SIGNATURE;
	HCRYPTKEY  phUserKey;
	HCRYPTKEY  phKey;
	
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0))
	{
		cout << "zashlo\n";
		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			cout << "ne poshlo\n";
	}
	else
	{
		cout << "vse norm\n";
	}
	if (CryptGetUserKey(hProv, AT_SIGNATURE, &phUserKey))
		cout << "got key" <<endl;
	else
	{
		cout << "generate key first" << endl;
		CryptGenKey(hProv, AT_SIGNATURE, 0, &phKey);
		if (!CryptGetUserKey(hProv, AT_SIGNATURE, &phUserKey))
			cout << "ne poshlo\n";
		cout << dwKeySpec<< " " << &phUserKey << endl;
	}
	
	
	HCRYPTHASH phHash;
	CryptCreateHash(hProv, CALG_MD5, 0, 0, &phHash);
	CryptHashData(phHash, (const BYTE*)cmp, strlen(cmp), 0);
	BYTE *pbSignature = NULL;
	DWORD dwSigLen;
	CryptSignHash(phHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen);
	pbSignature = (BYTE*)malloc(dwSigLen);
	CryptSignHash(phHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen);
	
HKEY hk; 
        DWORD test=1;     
        RegCreateKey(HKEY_CURRENT_USER, 
                _T("SOFTWARE\\iganich"),
                &hk);
	RegSetValueEx(hk,                    // subkey handle 
                _T("signature"),                // value name 
                0,                                        // must be zero 
                REG_SZ,                        // value type 
                (LPBYTE) pbSignature,                // pointer to value data 
                dwSigLen);       // length of value data 
	CryptDestroyHash(phHash);
    
    
}

int main()
{
	WIN32_FIND_DATA data;	
	char path[500] = {0};
	cout << "Enter path to install program\n";
	cin >> path;
	FindFirstFileA((const char*)path, &data);
	if(data.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
	{
		install_here(path);
	}
	else
	{
		if (CreateDirectory(path, NULL))
		{
			cout << "directory create" << endl;
			install_here(path);
		}
		else
			cout << "error create directory" << endl;
	}
	cout << path;
	return (0);
}
