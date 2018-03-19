#pragma once

#include <string>

namespace m4x1m1l14n
{
	namespace Crypto
	{
		namespace Random
		{
			std::string GenerateArray(size_t len);
			bool Generate(void * pData, size_t len);
			std::string GenerateString(size_t len, const std::string& chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
		}
	}
}
