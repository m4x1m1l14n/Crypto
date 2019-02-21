#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")

#include <Crypto\Hash.hpp>

#include <windows.h>
#include <wincrypt.h>

namespace m4x1m1l14n
{
	namespace Crypto
	{
		namespace Hash
		{
			std::string CalcHash(BCRYPT_ALG_HANDLE hAlgorithm, const std::string & szData)
			{
				std::string szHashData;
				DWORD dwBytesDone = 0;
				NTSTATUS bcryptResult = 0;
				DWORD dwObjectLength = 0;
				if ((bcryptResult = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (BYTE*)&dwObjectLength, sizeof(dwObjectLength), &dwBytesDone, 0)) == ERROR_SUCCESS)
				{
					DWORD dwHashLength = 0;
					if ((bcryptResult = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (BYTE*)&dwHashLength, sizeof(dwHashLength), &dwBytesDone, 0)) == ERROR_SUCCESS)
					{
						PBYTE pbHashObject = NULL;
						PBYTE pbHash = NULL;

						pbHashObject = (PBYTE)LocalAlloc(LMEM_FIXED, dwObjectLength);
						if (pbHashObject != nullptr)
						{
							pbHash = (PBYTE)LocalAlloc(LMEM_FIXED, dwHashLength);
							if (pbHash != nullptr)
							{
								BCRYPT_HASH_HANDLE hHash = NULL;
								if ((bcryptResult = BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, dwObjectLength, NULL, 0, 0)) == ERROR_SUCCESS)
								{
									if ((bcryptResult = BCryptHashData(hHash, (PBYTE)szData.c_str(), (ULONG)szData.size(), 0)) == ERROR_SUCCESS)
									{
										if ((bcryptResult = BCryptFinishHash(hHash, pbHash, dwHashLength, 0)) == ERROR_SUCCESS)
										{
											szHashData = std::string((char*)pbHash, dwHashLength);
										}
									}
									BCryptDestroyHash(hHash);
								}
								LocalFree(pbHash);
							}
							LocalFree(pbHashObject);
						}
					}
				}

				return szHashData;
			}

			std::string CalcHashWithSecret(BCRYPT_ALG_HANDLE hAlgorithm, const std::string & szData, const std::string & szSecret)
			{
				std::string szHashData;
				DWORD dwBytesDone = 0;
				NTSTATUS bcryptResult = 0;
				DWORD dwObjectLength = 0;
				if ((bcryptResult = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (BYTE*)&dwObjectLength, sizeof(dwObjectLength), &dwBytesDone, 0)) == ERROR_SUCCESS)
				{
					DWORD dwHashLength = 0;
					if ((bcryptResult = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (BYTE*)&dwHashLength, sizeof(dwHashLength), &dwBytesDone, 0)) == ERROR_SUCCESS)
					{
						PBYTE pbHashObject = NULL;
						PBYTE pbHash = NULL;

						pbHashObject = (PBYTE)LocalAlloc(LMEM_FIXED, dwObjectLength);
						if (pbHashObject != nullptr)
						{
							pbHash = (PBYTE)LocalAlloc(LMEM_FIXED, dwHashLength);
							if (pbHash != nullptr)
							{
								BCRYPT_HASH_HANDLE hHash = NULL;
								if ((bcryptResult = BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, dwObjectLength, (PBYTE)szSecret.c_str(), (ULONG)szSecret.size(), 0)) == ERROR_SUCCESS)
								{
									if ((bcryptResult = BCryptHashData(hHash, (PBYTE)szData.c_str(), (ULONG)szData.size(), 0)) == ERROR_SUCCESS)
									{
										if ((bcryptResult = BCryptFinishHash(hHash, pbHash, dwHashLength, 0)) == ERROR_SUCCESS)
										{
											szHashData = std::string((char*)pbHash, dwHashLength);
										}
									}
									BCryptDestroyHash(hHash);
								}
								LocalFree(pbHash);
							}
							LocalFree(pbHashObject);
						}
					}
				}

				return szHashData;
			}

			std::string Sha1(const std::string & szData)
			{
				std::string szHashData;
				BCRYPT_ALG_HANDLE hAlgorithm = 0;
				if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA1_ALGORITHM, NULL, 0) == ERROR_SUCCESS)
				{
					szHashData = CalcHash(hAlgorithm, szData);
					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}

				return szHashData;
			}

			std::string Sha256(const std::string & szData)
			{
				std::string szHashData;
				BCRYPT_ALG_HANDLE hAlgorithm = 0;
				if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) == ERROR_SUCCESS)
				{
					szHashData = CalcHash(hAlgorithm, szData);
					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}

				return szHashData;
			}

			std::string Sha512(const std::string & szData)
			{
				std::string szHashData;
				BCRYPT_ALG_HANDLE hAlgorithm = 0;
				if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA512_ALGORITHM, NULL, 0) == ERROR_SUCCESS)
				{
					szHashData = CalcHash(hAlgorithm, szData);
					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}

				return szHashData;
			}

			std::string MD5(const std::string & data)
			{
				std::string szHashData;
				BCRYPT_ALG_HANDLE hAlgorithm = NULL;

				if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_MD5_ALGORITHM, NULL, 0) == ERROR_SUCCESS)
				{
					szHashData = CalcHash(hAlgorithm, data);

					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}

				return szHashData;
			}

			std::string MD4(const std::string& data)
			{
				std::string szHashData;
				BCRYPT_ALG_HANDLE hAlgorithm = NULL;

				if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_MD4_ALGORITHM, NULL, 0) == ERROR_SUCCESS)
				{
					szHashData = CalcHash(hAlgorithm, data);

					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}

				return szHashData;
			}

			std::string HMACSha1(const std::string& szData, const std::string& szSecret)
			{
				std::string szHashData;
				BCRYPT_ALG_HANDLE hAlgorithm = NULL;

				if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) == ERROR_SUCCESS)
				{
					szHashData = CalcHashWithSecret(hAlgorithm, szData, szSecret);

					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}

				return szHashData;
			}

			std::string Pbkdf2Sha1(const std::string& szPassword, const std::string& szSalt, uint64_t rounds, uint32_t hashLen)
			{
				std::string szHashData;
				BCRYPT_ALG_HANDLE hAlgorithm = NULL;

				if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA1_ALGORITHM, MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG) == ERROR_SUCCESS)
				{
					PUCHAR pHash = (PUCHAR)LocalAlloc(LMEM_FIXED, hashLen);
					if (pHash != nullptr)
					{
						//STATUS_INVALID_HANDLE
						NTSTATUS ntst;
						if ((ntst = BCryptDeriveKeyPBKDF2(hAlgorithm, (PUCHAR)szPassword.c_str(), (ULONG)szPassword.length(), (PUCHAR)szSalt.c_str(), (ULONG)szSalt.length(), rounds, pHash, (ULONG)hashLen, 0)) == ERROR_SUCCESS)
						{
							szHashData = std::string((char*)pHash, hashLen);
						}

						LocalFree(pHash);
					}
					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}

				return szHashData;
			}
		}
	}
}
