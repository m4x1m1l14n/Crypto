#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ncrypt.lib")

#include <Crypto\Rsa.hpp>

#include <Windows.h>
#include <ncrypt.h>
#include <wincrypt.h>

namespace m4x1m1l14n
{
	namespace Crypto
	{
		class RsaImpl : public Rsa
		{
		public:
			RsaImpl(NCRYPT_PROV_HANDLE hProv, NCRYPT_KEY_HANDLE hPublicKey, NCRYPT_KEY_HANDLE hPrivateKey)
				: m_hProv(hProv)
				, m_hPublicKey(hPublicKey)
				, m_hPrivateKey(hPrivateKey)
			{}

			~RsaImpl()
			{
				if (m_hPublicKey) { NCryptFreeObject(m_hPublicKey); }
				if (m_hPrivateKey) { NCryptFreeObject(m_hPrivateKey); }
				if (m_hProv) { NCryptFreeObject(m_hProv); }
			}

			std::string Sign(const std::string & data)
			{
				std::string ret;

				BCRYPT_ALG_HANDLE hAlgoritmus = NULL;

				if (BCryptOpenAlgorithmProvider(&hAlgoritmus, NCRYPT_SHA512_ALGORITHM, NULL, 0) == 0)
				{
					DWORD dwHashObjectLength = 0;
					DWORD dwResultLength = 0;

					if (BCryptGetProperty(hAlgoritmus, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwHashObjectLength, sizeof(DWORD), &dwResultLength, 0) == 0)
					{
						PBYTE pHashObject = (PBYTE)LocalAlloc(0, dwHashObjectLength);
						if (pHashObject)
						{
							DWORD dwHashLength = 0;

							if (BCryptGetProperty(hAlgoritmus, BCRYPT_HASH_LENGTH, (PBYTE)&dwHashLength, sizeof(DWORD), &dwResultLength, 0) == 0)
							{
								PBYTE pHash = (PBYTE)LocalAlloc(0, dwHashLength);
								if (pHash)
								{
									BCRYPT_HASH_HANDLE hHash = NULL;

									if (BCryptCreateHash(hAlgoritmus, &hHash, pHashObject, dwHashObjectLength, NULL, 0, 0) == 0)
									{
										if (BCryptHashData(hHash, (PBYTE)data.c_str(), (ULONG)data.size(), 0) == 0)
										{
											if (BCryptFinishHash(hHash, pHash, dwHashLength, 0) == 0)
											{
												BCRYPT_PKCS1_PADDING_INFO PKCS1PaddingInfo = { 0 };
												DWORD dwSignature = 0;

												SECURITY_STATUS secStatus = NCryptSignHash(m_hPrivateKey, &PKCS1PaddingInfo, pHash, dwHashLength, NULL, 0, &dwSignature, NCRYPT_PAD_PKCS1_FLAG);
												if (secStatus == ERROR_SUCCESS)
												{
													PBYTE pSignature = (PBYTE)LocalAlloc(0, dwSignature);
													if (pSignature)
													{
														secStatus = NCryptSignHash(m_hPrivateKey, &PKCS1PaddingInfo, pHash, dwHashLength, pSignature, dwSignature, &dwSignature, NCRYPT_PAD_PKCS1_FLAG);
														if (secStatus == ERROR_SUCCESS)
														{
															ret = std::string((const char*)pSignature, dwSignature);
														}

														LocalFree(pSignature);
													}
												}
											}
										}

										BCryptDestroyHash(hHash);
									}

									LocalFree(pHash);
								}
							}

							LocalFree(pHashObject);
						}
					}

					BCryptCloseAlgorithmProvider(hAlgoritmus, 0);
				}

				return ret;
			}

			bool Verify(const std::string & encryptedData, const std::string& signature)
			{
				auto success = false;

				BCRYPT_ALG_HANDLE hAlgoritmus = NULL;

				if (BCryptOpenAlgorithmProvider(&hAlgoritmus, NCRYPT_SHA512_ALGORITHM, NULL, 0) == 0)
				{
					DWORD dwHashObjectLength = 0;
					DWORD dwResultLength = 0;

					if (BCryptGetProperty(hAlgoritmus, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwHashObjectLength, sizeof(DWORD), &dwResultLength, 0) == 0)
					{
						PBYTE pHashObject = (PBYTE)LocalAlloc(0, dwHashObjectLength);
						if (pHashObject)
						{
							DWORD dwHashLength = 0;

							if (BCryptGetProperty(hAlgoritmus, BCRYPT_HASH_LENGTH, (PBYTE)&dwHashLength, sizeof(DWORD), &dwResultLength, 0) == 0)
							{
								PBYTE pHash = (PBYTE)LocalAlloc(0, dwHashLength);
								if (pHash)
								{
									BCRYPT_HASH_HANDLE hHash = NULL;

									if (BCryptCreateHash(hAlgoritmus, &hHash, pHashObject, dwHashObjectLength, NULL, 0, 0) == 0)
									{
										if (BCryptHashData(hHash, (PBYTE)encryptedData.c_str(), (ULONG)encryptedData.size(), 0) == 0)
										{
											if (BCryptFinishHash(hHash, pHash, dwHashLength, 0) == 0)
											{
												BCRYPT_PKCS1_PADDING_INFO PKCS1PaddingInfo = { 0 };
												/*DWORD dwSignature = 0;*/

												SECURITY_STATUS secStatus = NCryptVerifySignature(m_hPublicKey, &PKCS1PaddingInfo, pHash, dwHashLength, (PBYTE)signature.c_str(), (DWORD)signature.length(), NCRYPT_PAD_PKCS1_FLAG);

												success = (secStatus == ERROR_SUCCESS);
											}
										}

										BCryptDestroyHash(hHash);
									}

									LocalFree(pHash);
								}
							}
						}
						LocalFree(pHashObject);
					}

					BCryptCloseAlgorithmProvider(hAlgoritmus, 0);

				}

				return success;
			}

			std::string PublicEncrypt(const std::string & data)
			{
				std::string ret;

				PBYTE pEncrypted = NULL;
				DWORD dwEncrypted = 0;

				BCRYPT_OAEP_PADDING_INFO paddingInfo;
				paddingInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;
				paddingInfo.pbLabel = NULL;
				paddingInfo.cbLabel = 0;

				SECURITY_STATUS secStatus = NCryptEncrypt(m_hPublicKey, (PBYTE)data.c_str(), (DWORD)data.length(), &paddingInfo, pEncrypted, dwEncrypted, &dwEncrypted, NCRYPT_PAD_OAEP_FLAG);
				if (secStatus == ERROR_SUCCESS)
				{
					pEncrypted = (PBYTE)LocalAlloc(0, dwEncrypted);
					if (pEncrypted)
					{
						secStatus = NCryptEncrypt(m_hPublicKey, (PBYTE)data.c_str(), (DWORD)data.length(), &paddingInfo, pEncrypted, dwEncrypted, &dwEncrypted, NCRYPT_PAD_OAEP_FLAG);
						if (secStatus == ERROR_SUCCESS)
						{
							ret = std::string((const char*)pEncrypted, dwEncrypted);
						}

						LocalFree(pEncrypted);
					}
				}

				return ret;
			}

			std::string PrivateDecrypt(const std::string & encryptedData)
			{
				std::string ret;

				PBYTE pDecrypted = NULL;
				DWORD dwDecrypted = 0;

				BCRYPT_OAEP_PADDING_INFO paddingInfo;
				paddingInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;
				paddingInfo.pbLabel = NULL;
				paddingInfo.cbLabel = 0;

				SECURITY_STATUS secStatus = NCryptDecrypt(m_hPrivateKey, (PBYTE)encryptedData.c_str(), (DWORD)encryptedData.length(), &paddingInfo, pDecrypted, dwDecrypted, &dwDecrypted, NCRYPT_PAD_OAEP_FLAG);
				if (secStatus == ERROR_SUCCESS)
				{
					pDecrypted = (PBYTE)LocalAlloc(0, dwDecrypted);
					if (pDecrypted)
					{
						secStatus = NCryptDecrypt(m_hPrivateKey, (PBYTE)encryptedData.c_str(), (DWORD)encryptedData.length(), &paddingInfo, pDecrypted, dwDecrypted, &dwDecrypted, NCRYPT_PAD_OAEP_FLAG);
						if (secStatus == ERROR_SUCCESS)
						{
							ret = std::string((const char*)pDecrypted, dwDecrypted);
						}

						LocalFree(pDecrypted);
					}
				}

				return ret;
			}

		private:
			NCRYPT_PROV_HANDLE m_hProv;
			NCRYPT_KEY_HANDLE m_hPublicKey;
			NCRYPT_KEY_HANDLE m_hPrivateKey;
		};

		Rsa::Rsa() {}

		Rsa_ptr Rsa::Create(const std::string & publicKey, const std::string & privateKey)
		{
			Rsa_ptr rsa;

			NCRYPT_PROV_HANDLE hProv = NULL;
			NCRYPT_KEY_HANDLE hPublicKey = NULL;
			NCRYPT_KEY_HANDLE hPrivateKey = NULL;

			SECURITY_STATUS secStatus = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
			if (secStatus == ERROR_SUCCESS && !publicKey.empty())
			{
				secStatus = NCryptImportKey(hProv, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, &hPublicKey, (PBYTE)publicKey.c_str(), (DWORD)publicKey.length(), 0);
			}

			if (secStatus == ERROR_SUCCESS && !privateKey.empty())
			{
				secStatus = NCryptImportKey(hProv, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, &hPrivateKey, (PBYTE)privateKey.c_str(), (DWORD)privateKey.length(), 0);
			}

			if (secStatus == ERROR_SUCCESS)
			{
				auto pRsa = new RsaImpl(hProv, hPublicKey, hPrivateKey);

				rsa = std::shared_ptr<Rsa>(pRsa);
			}
			else
			{
				if (hPublicKey) { NCryptFreeObject(hPublicKey); }
				if (hPrivateKey) { NCryptFreeObject(hPrivateKey); }
				if (hProv) { NCryptFreeObject(hProv); }
			}

			return rsa;
		}

		std::string Rsa::PublicEncrypt(const std::string & publicKey, const std::string & data)
		{
			std::string ret;
			auto rsa = Rsa::Create(publicKey, "");
			if (rsa) {
				ret = rsa->PublicEncrypt(data);
			}

			return ret;
		}

		std::string Rsa::PrivateDecrypt(const std::string & privateKey, const std::string & encryptedData)
		{
			std::string ret;
			auto rsa = Rsa::Create("", privateKey);
			if (rsa) {
				ret = rsa->PrivateDecrypt(encryptedData);
			}

			return ret;
		}

		std::string Rsa::Sign(const std::string & privateKey, const std::string & data)
		{
			std::string ret;
			auto rsa = Rsa::Create("", privateKey);
			if (rsa) {
				ret = rsa->Sign(data);
			}

			return ret;
		}

		bool Rsa::Verify(const std::string & publicKey, const std::string & encryptedData, const std::string & signature)
		{
			bool ret = false;
			auto rsa = Rsa::Create(publicKey, "");
			if (rsa) {
				ret = rsa->Verify(encryptedData, signature);
			}

			return ret;
		}
	}
}
