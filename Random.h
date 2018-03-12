#pragma once
#include <string>

namespace Crypto
{
	namespace Random
	{
		std::string GenerateArray(size_t len);
		bool Generate(void * pData, size_t len);
	}
}
