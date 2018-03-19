#pragma comment(lib, "Bcrypt.lib")

#include <Crypto\AesCBC.hpp>
#include <Crypto\Hash.hpp>

#include <Windows.h>
#include <Bcrypt.h>

namespace m4x1m1l14n
{
	namespace Crypto
	{

		class AesCBCImpl : public AesCBC
		{
		public:
			AesCBCImpl(BCRYPT_ALG_HANDLE algHandle, BCRYPT_KEY_HANDLE keyHandle, const std::string& iv)
				: m_pAlgorithm(algHandle)
				, m_pKey(keyHandle)
				, m_iv(iv)
			{

			}

			~AesCBCImpl()
			{
				if (m_pKey) { BCryptDestroyKey(m_pKey); }
				if (m_pAlgorithm) { BCryptCloseAlgorithmProvider(m_pAlgorithm, 0); }
			}

			// Inherited via AesCBC
			virtual std::string Encrypt(const std::string & data) override
			{
				std::string ret;

				ULONG ulEncrypted = 0;

				auto iv = m_iv;

				NTSTATUS status = BCryptEncrypt(m_pKey, (PUCHAR)data.c_str(), (ULONG)data.length(), nullptr, (PUCHAR)iv.c_str(), (ULONG)iv.length(), nullptr, 0, &ulEncrypted, BCRYPT_BLOCK_PADDING);
				if (BCRYPT_SUCCESS(status))
				{
					BYTE *pEncrypted = (BYTE*)LocalAlloc(0, ulEncrypted);
					if (pEncrypted)
					{
						ULONG ulResult = 0;

						status = BCryptEncrypt(m_pKey, (PUCHAR)data.c_str(), (ULONG)data.length(), nullptr, (PUCHAR)iv.c_str(), (ULONG)iv.length(), pEncrypted, ulEncrypted, &ulResult, BCRYPT_BLOCK_PADDING);
						if (BCRYPT_SUCCESS(status))
						{
							ret = std::string((const char*)pEncrypted, ulEncrypted);
						}

						LocalFree(pEncrypted);
					}
				}

				return ret;
			}

			virtual std::string Decrypt(const std::string & data) override
			{
				std::string ret;

				ULONG ulDecrypted = 0;

				auto iv = m_iv;

				NTSTATUS status = BCryptDecrypt(m_pKey, (PUCHAR)data.c_str(), (ULONG)data.length(), nullptr, (PUCHAR)iv.c_str(), (ULONG)iv.length(), nullptr, 0, &ulDecrypted, BCRYPT_BLOCK_PADDING);
				if (BCRYPT_SUCCESS(status))
				{
					BYTE *pDecrypted = (BYTE*)LocalAlloc(0, ulDecrypted);
					if (pDecrypted)
					{
						ULONG ulResult = 0;

						status = BCryptDecrypt(m_pKey, (PUCHAR)data.c_str(), (ULONG)data.length(), nullptr, (PUCHAR)iv.c_str(), (ULONG)iv.length(), pDecrypted, ulDecrypted, &ulResult, BCRYPT_BLOCK_PADDING);
						if (BCRYPT_SUCCESS(status))
						{
							ret = std::string((const char*)pDecrypted, ulResult);
						}

						LocalFree(pDecrypted);
					}
				}

				return ret;
			}

		private:
			BCRYPT_ALG_HANDLE m_pAlgorithm;
			BCRYPT_KEY_HANDLE m_pKey;
			std::string m_iv;
		};

		AesCBC::AesCBC() { }

		AesCBC_ptr AesCBC::Create(const std::string& iv, const std::string& secret)
		{
			AesCBC_ptr aes;

			BCRYPT_ALG_HANDLE pAlgorithm = nullptr;
			BCRYPT_KEY_HANDLE pKey = nullptr;

			NTSTATUS status = BCryptOpenAlgorithmProvider(&pAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0);
			if (BCRYPT_SUCCESS(status))
			{
				status = BCryptSetProperty(pAlgorithm, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
				if (BCRYPT_SUCCESS(status))
				{
					ULONG ulResult = 0;
					DWORD dwBlockLength = 0;

					status = BCryptGetProperty(pAlgorithm, BCRYPT_BLOCK_LENGTH, (PUCHAR)&dwBlockLength, sizeof(dwBlockLength), &ulResult, 0);
					if (BCRYPT_SUCCESS(status))
					{
						DWORD dwFlags = 0;

						auto hashSecret = Crypto::Hash::MD5(secret);

						status = BCryptGenerateSymmetricKey(pAlgorithm, &pKey, nullptr, 0, (PUCHAR)hashSecret.c_str(), (ULONG)hashSecret.length(), dwFlags);
						if (BCRYPT_SUCCESS(status))
						{
							auto hashIV = Crypto::Hash::MD5(iv);

							auto pAes = new AesCBCImpl(pAlgorithm, pKey, hashIV);

							aes = std::shared_ptr<AesCBC>(pAes);
						}
					}
				}
			}

			if (!aes)
			{
				if (pKey) { BCryptDestroyKey(pKey); }
				if (pAlgorithm) { BCryptCloseAlgorithmProvider(pAlgorithm, 0); }
			}

			return aes;
		}
	}
}
