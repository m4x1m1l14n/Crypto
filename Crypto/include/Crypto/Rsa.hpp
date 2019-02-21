#pragma once

#include <string>
#include <memory>

namespace m4x1m1l14n
{
	namespace Crypto
	{
		class Rsa;

		typedef std::shared_ptr<Rsa> Rsa_ptr;

		class Rsa
		{
		protected:
			Rsa();

		public:
			static Rsa_ptr Create(const std::string& publicKey, const std::string& privateKey);

			static std::string PublicEncrypt(const std::string & publicKey, const std::string & data);
			static std::string PrivateDecrypt(const std::string & privateKey, const std::string & encryptedData);

			static std::string Sign(const std::string& privateKey, const std::string& data);
			static bool Verify(const std::string & publicKey, const std::string & encryptedData, const std::string& signature);

			// virtuals
			virtual std::string PublicEncrypt(const std::string & data) = 0;
			virtual std::string PrivateDecrypt(const std::string & encryptedData) = 0;

			virtual std::string Sign(const std::string& data) = 0;
			virtual bool Verify(const std::string & encryptedData, const std::string& signature) = 0;
		};
	}
}
