#pragma once

#include <string>

namespace m4x1m1l14n
{
	namespace Crypto
	{
		namespace Base64
		{
			std::string Decode(const std::string& s);
			std::string Encode(const std::string& s);
		};
	}
}
