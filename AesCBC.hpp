#pragma once

#include <string>
#include <memory>

namespace m4x1m1l14n
{
	namespace Crypto
	{
		class AesCBC;

		typedef std::shared_ptr<AesCBC> AesCBC_ptr;

		class AesCBC
		{
		protected:
			AesCBC();

		public:
			static AesCBC_ptr Create(const std::string& iv, const std::string& secret);

			virtual std::string Encrypt(const std::string& data) = 0;
			virtual std::string Decrypt(const std::string& data) = 0;
		};
	}
}
