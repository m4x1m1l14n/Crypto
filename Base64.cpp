#pragma comment(lib, "Crypt32.lib")

#include <Crypto\Base64.hpp>

#include <Windows.h>
#include <Wincrypt.h>

namespace m4x1m1l14n
{
	std::string Crypto::Base64::Decode(const std::string& s)
	{
		std::string decodedString;

		DWORD dwLength = 0;

		BOOL fReturn = CryptStringToBinaryA(s.c_str(), (DWORD)s.length(), CRYPT_STRING_BASE64, nullptr, &dwLength, nullptr, nullptr);
		if (fReturn) 
		{
			char *pBuffer = (char*)LocalAlloc(0, dwLength);
			if (pBuffer) 
			{
				fReturn = CryptStringToBinaryA(s.c_str(), (DWORD)s.length(), CRYPT_STRING_BASE64, (BYTE*)pBuffer, &dwLength, nullptr, nullptr);
				if (fReturn) 
				{
					decodedString = std::string(pBuffer, dwLength);
				}

				LocalFree(pBuffer);
			}
		}

		return decodedString;
	}

	std::string Crypto::Base64::Encode(const std::string& s)
	{
		std::string encodedString;

		DWORD dwLength = 0;
		
		BOOL fReturn = CryptBinaryToStringA((const BYTE*)s.c_str(), (DWORD)s.length(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &dwLength);
		if (fReturn)
		{
			char* pBuffer = (char*)LocalAlloc(0, dwLength);
			if (pBuffer) 
			{
				fReturn = CryptBinaryToStringA((const BYTE*)s.c_str(), (DWORD)s.length(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, pBuffer, &dwLength);
				if (fReturn)
				{
					encodedString = std::string(pBuffer, dwLength);
				}

				LocalFree(pBuffer);
			}
		}

		return encodedString;
	}
}
