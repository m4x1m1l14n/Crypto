#include <Crypto\Random.h>

#include <windows.h>
#include <wincrypt.h>


std::string Crypto::Random::GenerateArray(size_t len)
{
	std::string ret;

	HCRYPTPROV hCryptProv = 0;

	BOOL fSuccess = CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, 0);
	if (!fSuccess && GetLastError() == NTE_BAD_KEYSET)
	{
		fSuccess = CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET);
	}

	if (fSuccess)
	{
		LPBYTE pbData = (LPBYTE)LocalAlloc(0, len);
		if (pbData)
		{
			if (CryptGenRandom(hCryptProv, (DWORD)len, pbData))
			{
				ret = std::string((const char*)pbData, len);
			}

			LocalFree(pbData);
		}

		CryptReleaseContext(hCryptProv, 0);
	}

	return ret;
}

bool Crypto::Random::Generate(void * pData, size_t len)
{
	HCRYPTPROV hCryptProv = 0;

	BOOL fSuccess = CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, 0);
	if (!fSuccess && GetLastError() == NTE_BAD_KEYSET) 
	{
		fSuccess = CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET);
	}

	if (fSuccess) 
	{
		fSuccess = CryptGenRandom(hCryptProv, (DWORD)len, (BYTE*)pData);
	}

	if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); }

	return fSuccess ? true : false;
}
