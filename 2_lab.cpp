#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <Lmcons.h>
#include <windows.h>
#include <wincrypt.h>
#include <tchar.h>

using namespace std;

struct		t_user{
	const char	*user_name;
	int			pass_len;
	const char	*pass;
	int			is_blocked;
	int			is_restrict;
};

char *custom_strcat(char *first, const char *second)
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

void write_changes(t_user *us)
{
	char *path = custom_strcat((char*)"./users/", us->user_name);
	ofstream ouser;
	ouser.open(path, ios::binary);
	char *buffer = (char*)malloc(20);
	itoa(us->pass_len, buffer, 10);
	ouser.write((const char*)us->user_name, strlen(us->user_name));
	ouser.write("\n", 1);
	ouser.write((const char*)buffer, strlen(buffer));
	ouser.write("\n", 1);
	ouser.write((const char*)us->pass, us->pass_len);
	ouser.write("\n", 1);
	ouser.write((const char*)(&(us->is_blocked)), 1);
	ouser.write("\n", 1);
	ouser.write((const char*)(&(us->is_restrict)), 1);
	ouser.write("\n", 1);
	ouser.close();
	free(buffer);
	free(path);
}

void create_admin()
{
	ofstream ouser;
	ouser.open("./users/ADMIN", ios::binary);
	cout << "ADMIN not found. creating." << endl;
	t_user adm;
	adm.user_name = "ADMIN";
	adm.pass_len = 0;
	adm.pass = "";
	adm.is_blocked = '0';
	adm.is_restrict = '1';
	write_changes(&adm);
	ouser.close();
}

void	creating_file(const char *username)
{
	ofstream ouser;
	char *path = custom_strcat((char*)"./users/", username);
	ouser.open(path, ios::binary);
	cout << "Creating user file " << username << endl;
	t_user user;
	user.user_name = username;
	user.pass_len = 0;
	user.pass = "";
	user.is_blocked = 0;
	user.is_restrict = 0;
	write_changes(&user);
	ouser.close();
	free(path);
}

void	get_user(const char *username, ifstream *iuser)
{
	char *path = custom_strcat((char*)"./users/", username);
	(*iuser).open(path, ios::binary);
	free(path);
}
	
void	read_user(t_user *us, ifstream *iuser)
{
	string buffer;
	int count = 0;
	while (getline(*iuser, buffer))
	{
		count++;
		switch (count)
		{
			case 2:
			{
				us->pass_len = atoi (buffer.c_str());
				break;
			}
			case 3:
			{
				us->pass = strdup(buffer.c_str());
				break;
			}
			case 4:
			{
				us->is_blocked = atoi(buffer.c_str()) + 48;
				break;
			}
			case 5:
			{
				us->is_restrict = atoi(buffer.c_str()) + 48;
				buffer;	
			}
		}
	}
}

int		freereturn(t_user &us)
{
	free((void*)us.user_name);
	free((void*)us.pass);
	return (0);
}

int		check_password(const char *pass)
{
	if (!*pass)
		return (1);
	char buffer[100];
	for (int count = 0; count < 3; count++)
	{
		cout << "enter password or EXIT to stop\n";
		cin >> buffer;
		if (!strcmp(buffer, "EXIT"))
			return (2);
		if (!strcmp(pass, buffer))
			return (1);
		cout << "Wrong pass" << endl;
	}
	return (0);
}

int		check_pass_correct(char *buffer)
{
	int is_let = 0;
	int is_math = 0;

	for (int i = 0; buffer[i] != 0 && (is_let + is_math != 2); i++)
	{
		if ((buffer[i] >= 'A' && buffer[i] <= 'Z') || (buffer[i] >= 'a' && buffer[i] <= 'z'))
		{
			is_let = 1;
			continue;
		}
		if (buffer[i] == '+' || buffer[i] == '-' || buffer[i] == '*' || buffer[i] == '/' || buffer[i] == '%')
			is_math = 1;
	}
	return (is_let + is_math);
}

int		change_pass(t_user *us)
{
	int ret = 0;
	char buffer[100];

	if ((ret = check_password(us->pass)) == 1)
	{
		cout << "Enter new password\n";
		while (1)
		{
			cin >> buffer;
			if (strlen(buffer) > 20)
			{
				cout << "Enter pass 1-20 symbols\n";
				continue;
			}
			if (us->is_restrict == '1' && check_pass_correct(buffer) != 2)
			{
				cout << "Pass must include letters and math symbols\n";
				continue;
			}
			break;
		}
		free((void*)us->pass);
		us->pass_len = strlen(buffer);
		us->pass = strdup(buffer);
		write_changes(us);
	}
	else if (ret == 0)
		return (0);
	return (1);
}

void	get_info_users()
{
	int count = 0;
	DIR *dir;
	struct dirent *ent;
	ifstream iuser;
	t_user temp_user;
	if ((dir = opendir ("./users/")) != NULL) 
	{
		/* print all the files and directories within directory */
		while ((ent = readdir (dir)) != NULL) 
		{
			count++;
			if (count < 3)
				continue;
			printf("user - %s\n", ent->d_name);
			get_user(ent->d_name, &iuser);
			read_user(&temp_user, &iuser);
			cout << "Is banned - ?: " << (char)(temp_user.is_blocked) << endl;
			cout << "Is pass restricted - ?: " << (char)(temp_user.is_restrict) << endl;
			iuser.close();
			free((void*)temp_user.pass);
		}
		closedir (dir);
	}
	else
		cout << "error reading users\n";
}

void	add_new_user()
{
	char buffer[100];
	cout << "Enter name of new user\n";
	cin >> buffer;
	while (1)
	{
		if (strchr(buffer, '\n'))
		{
			cout << "Forbidden symbol in name\n";
			continue;
		}
		break;		
	}
	ifstream check;
	get_user(buffer, &check);
	if (!check)
		creating_file(buffer);
	else
		cout << "This user already exists\n";
}

void	ban_user()
{
	char buffer[100];
	int choise;
	cout << "Enter user's name\n";
	cin >> buffer;
	ifstream check;
	get_user(buffer, &check);
	t_user user;
	if (check)
	{
		cout << "Enter flag for ban/unban\n";
		cin >> choise;
		read_user(&user, &check);
		check.close();
		user.is_blocked = choise + 48;
		user.user_name = buffer;
		write_changes(&user);
		free ((void*)user.pass);
	}
	else
		cout << "This user does not exists\n";
}

void	district_pass()
{
	char buffer[100];
	int choise;
	cout << "Enter user's name\n";
	cin >> buffer;
	ifstream check;
	get_user(buffer, &check);
	t_user user;
	if (check)
	{
		read_user(&user, &check);
		check.close();
		cout << "Enter flag for restrict\n";
		cin >> choise;
		user.is_restrict = choise + 48;
		user.user_name = buffer;
		write_changes(&user);
		free ((void*)user.pass);
	}
	else
		cout << "This user does not exists\n";
}

void	get_info_program()
{
	cout << "author: Igor Ganich, FB-63\nRestrict for password: letters and math symblols\n";
}

void	admin_mode(t_user &user)
{
	int choise = 0;
	cout << "You logged in as ADMIN" << endl;
	while (choise != 7)
	{
		cout << "Enter your option:\n1 - Change admin's pass\n2 - Get info about all users\n3 - Add new user\n4 - Ban/unban user\n5 - restrict pass for user\n6 - Get info about program\n7 - Exit\n";
		cin >> choise;
		switch (choise)
		{
			case 1:
			{
				if (!change_pass(&user))
					return ;
				break;
			}
			case 2:
			{
				get_info_users();
				break;
			}
			case 3:
			{
				add_new_user();
				break;
			}
			case 4:
			{
				ban_user();
				break;
			}
			case 5:
			{
				district_pass();
				break;
			}
			case 6:
			{
				get_info_program();
				break;
			}
			case 7:
			{
				return ;
			}
			default:
			{
				cout << "wrong option\n";
				break ;
			}
		}
	}
}

void	simple_mode(t_user &user)
{
	int choise = 0;
	cout << "You logged in as " << user.user_name << endl;
	while (choise != 3)
	{
		cout << "Enter your option:\n1 - Change password\n2 - Get info about program\n3 - End work\n";
		cin >> choise;
		switch(choise)
		{
			case 1:
			{
				if (!change_pass(&user))
					return ;
				break;
			}
			case 2:
			{
				get_info_program();
				break;
			}
			case 3:
			{
				return ;
			}
			default:
			{
				cout << "wrong option\n";
				break;	
			}
		}
	}
}

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


int		check_pirate()
{
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
	_TCHAR szPATH[] = _T("Software\\iganich\\");
	HKEY hKey;
	HCRYPTPROV hProv;
	DWORD      dwKeySpec = AT_SIGNATURE;
	HCRYPTKEY  phUserKey;
	HCRYPTKEY  phKey;
	HCRYPTHASH phHash;
	DWORD dwSigLen;
	// GET HASH OF DATA
		

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0))
	{
		cout << "zashlo\n";
		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			cout << "ne poshlo\n";
	}	
	
	CryptCreateHash(hProv, CALG_MD5, 0, 0, &phHash);
	CryptHashData(phHash, (const BYTE*)cmp, strlen(cmp), 0);
	BYTE *pbSignature = NULL;
	CryptSignHash(phHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen);
//	pbSignature = (BYTE*)malloc(dwSigLen);
//	CryptSignHash(phHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen);
	CryptDestroyHash(phHash);
	
	if (RegCreateKeyEx(HKEY_CURRENT_USER, szPATH, 0, NULL, REG_OPTION_VOLATILE, KEY_READ, NULL, &hKey, NULL) != ERROR_SUCCESS)
		cout << "ne poluchilos create key\n";
	LPDWORD value_length;
	DWORD dwType = REG_SZ;
	TCHAR BUF[255] = {0};
	DWORD ssiz = sizeof(BUF);
	if (RegOpenKeyEx (HKEY_CURRENT_USER, szPATH, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
	{
		RegQueryValueEx(hKey, _T("Signature"), NULL, &dwType, (LPBYTE)BUF, &ssiz);
	}
//	if (RegQueryValueEx(hKey, _T("Signature"), NULL, &dwType, (LPBYTE)&pbSignature, value_length))
//		cout << "ne vishlo\n";
	
	CryptCreateHash(hProv, CALG_MD5, 0, 0, &phHash);
	CryptHashData(phHash, (const BYTE*)cmp, strlen(cmp), 0);
	CryptGetUserKey(hProv, AT_SIGNATURE, &phUserKey);
	return (CryptVerifySignature(phHash, (BYTE*)BUF, dwSigLen, phUserKey, NULL, 0));
}

int		main(int argc, char **argv)
{
	if (!check_pirate())
	{
		cout << "zamecheno nesankcionirovannoe kopirovanie\n";
		cin >> argc;
		return (-1);
	}
	ofstream	ouser;
	ifstream	iuser;
	int			logged = 0;
	t_user		us;
	char		*username = (char*)malloc(21);

	us.user_name = username;
	get_user("ADMIN", &iuser);
	if (!iuser)
		create_admin();
	iuser.close();
	while (!logged)
	{
		iuser.clear();
		cout << "enter your name or EXIT to leave program\n";
		cin >> username;
		if (!strcmp(username, "EXIT"))
		{
			free(username);
			return (0);
		}
		get_user(username, &iuser);
		if (!iuser)
			cout << username << " not found. Enter exist username.\n";
		else
			logged = 1;
	}
	read_user(&us, &iuser);
	iuser.close();
	if (us.is_blocked == '1')
	{
		cout << "You was banned by admin\n";
		return (freereturn(us));
	}
	if (check_password(us.pass) != 1)
		return (freereturn(us));
	cout << "Successfully logged in\n";
	if (!strcmp(us.user_name, "ADMIN"))
		admin_mode(us);
	else
		simple_mode(us);
	cin >> logged;
	return (0);
}
