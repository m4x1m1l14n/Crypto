#pragma comment(lib, "Crypt32.lib")

#include <Crypto\Hex.hpp>

#include <Windows.h>
#include <wincrypt.h>

namespace m4x1m1l14n
{
	std::string Crypto::Hex::Encode(const std::string& data)
	{
		return Crypto::Hex::Encode(data.c_str(), data.length());
	}

	std::string Crypto::Hex::Encode(const void* pData, size_t len)
	{
		std::string encoded;

		DWORD dwLength = 0;

		BOOL fResult = CryptBinaryToStringA((BYTE*)pData, (DWORD)len, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, nullptr, &dwLength);
		if (fResult)
		{
			auto pBuffer = (char*)LocalAlloc(0, dwLength);
			if (pBuffer)
			{
				fResult = CryptBinaryToStringA((BYTE*)pData, (DWORD)len, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, pBuffer, &dwLength);
				if (fResult)
				{
					encoded = std::string(pBuffer, dwLength);
				}

				LocalFree(pBuffer);
			}
		}

		return encoded;
	}

	std::string Crypto::Hex::Decode(const std::string& s)
	{
		std::string decoded;

		DWORD dwLength = 0;

		BOOL fResult = CryptStringToBinaryA(s.c_str(), (DWORD)s.length(), CRYPT_STRING_HEXRAW, nullptr, &dwLength, nullptr, nullptr);
		if (fResult)
		{
			auto pBuffer = (BYTE*)LocalAlloc(0, dwLength);
			if (pBuffer)
			{
				fResult = CryptStringToBinaryA(s.c_str(), (DWORD)s.length(), CRYPT_STRING_HEXRAW, pBuffer, &dwLength, nullptr, nullptr);
				if (fResult)
				{
					decoded = std::string((char*)pBuffer, dwLength);
				}

				LocalFree(pBuffer);
			}
		}

		return decoded;
	}
}
