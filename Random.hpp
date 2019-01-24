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

			template<typename T,typename = std::enable_if_t<std::is_integral<T>::value>>
			inline T Generate(const T min = std::numeric_limits<T>::min(), const T max = std::numeric_limits<T>::max())
			{
				if (min >= max)
				{
					throw std::invalid_argument("\"min\" {" + std::to_string(min) + "} must be less than \"max\" {" + std::to_string(max) + "}");
				}

				T val;

				Generate(&val, sizeof(val));

				val = (val % ((max - min) + 1)) + min;

				return val;
			}
		};
	}
}
