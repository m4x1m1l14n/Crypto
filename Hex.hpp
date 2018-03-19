#pragma once

#include <string>

namespace m4x1m1l14n
{
	namespace Crypto
	{
		namespace Hex
		{
			std::string Encode(const std::string& data);
			std::string Encode(const void* pData, size_t len);

			std::string Decode(const std::string& buf);
		}
	}
}
