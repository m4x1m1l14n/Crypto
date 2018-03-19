#pragma once
#include <string>

namespace m4x1m1l14n
{
	namespace Crypto
	{
		namespace Hash
		{
			std::string Sha1(const std::string & szData);
			std::string Sha256(const std::string & szData);
			std::string Sha512(const std::string & szData);
			std::string MD5(const std::string& data);
			std::string MD4(const std::string& data);
			std::string HMACSha1(const std::string& szData, const std::string& szSecret);
			std::string Pbkdf2Sha1(const std::string& szPassword, const std::string& szSalt, uint64_t rounds, uint32_t hashLen);
		}
	}
}
