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

			template <
				typename T, 
				typename = std::enable_if_t<std::is_integral<T>::value>
			>
			inline T Generate
			(
				T min = std::numeric_limits<T>::min(), 
				T max = std::numeric_limits<T>::max()
			)
			{
				T val;

				Generate(&val, sizeof(val));

				if (min > max)
				{
					min ^= max; max ^= min; min ^= max;
				}

				const T& mod = (max - min) + 1;
				if (mod)
				{
					val %= mod;
				}

				val = (val < 0 ? (val * -1) : val) + min;

				return val;
			}
		};
	}
}
