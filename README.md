# Crypto
C++ wrappers for Windows Crypto &amp; Crypto Next Generation API

## Table of contents
1. [Crypto::Random namespace]
2. [Crypto::Hex namespace]

## Crypto::Random namespace
### Methods
#### Crypto::Random::Generate method
Generating random basic data types

```C++
#include <Crypto\Random.hpp>

using namespace m4x1m1l14n;

uint8_t u8rand;
uint16_t u16rand;
uint32_t u32rand;
uint64_t u64rand;

Crypto::Random::Generate(&u8rand, sizeof(u8rand));
Crypto::Random::Generate(&u16rand, sizeof(u16rand));
Crypto::Random::Generate(&u32rand, sizeof(u32rand));
Crypto::Random::Generate(&u64rand, sizeof(u64rand));
```

#### Crypto::Random::GenerateArray method
Generating random arrays. Raw data is generated, so to convert them into text representation use some of the binary-to-text encoding functions (Base64, HEX)

```C++
#include <Crypto\Random.hpp>

using namespace m4x1m1l14n;

size_t arrlen = 32;

std::string randarr = Crypto::Random::GenerateArray(arrlen);
```

#### Crypto\::Random\::GenerateString method
Generating random strings.

```C++
#include <Crypto\Random.hpp>

using namespace m4x1m1l14n;

size_t len = 16;

std::string s = Crypto::Random::GenerateString(len);
```

Default characters that method use for string generation is "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".

If you want to specify characters that string can contain simply change input characters set

```C++
#include <Crypto\Random.hpp>

using namespace m4x1m1l14n;

size_t len = 16;

std::string s = Crypto::Random::GenerateString(len, "ABCDEFGHIJKLMnopqrstuvwxyz6789");
```

## Crypto::Hex namespace
### Methods
#### Crypto::Hex::Encode method
HEX encode input data

```C++
#include <Crypto\Hex.hpp>

using namespace m4x1m1l14n;

std::string encoded = Crypto::Hex::Encode("Data to be HEX encoded");

/* encoded = "4461746120746f2062652048455820656e636f646564" */
```
Or you can HEX encode any data types, arrays etc.

```C++
#include <Crypto\Hex.hpp>
#include <Crypto\Random.hpp>

using namespace m4x1m1l14n;

uint8_t u8val = 0xaa;
uint16_t u16val = 0xaaaa;
uint32_t u32val = 0xaaaaaaaa;
uint64_t u64val = 0xaaaaaaaaaaaaaaaa;

std::string encoded;

encoded = Crypto::Hex::Encode(&u8val, sizeof(u8val));

/* encoded = "aa" */

encoded = Crypto::Hex::Encode(&u16val, sizeof(u16val));

/* encoded = "aaaa" */

encoded = Crypto::Hex::Encode(&u32val, sizeof(u32val));

/* encoded = "aaaaaaaa" */

encoded = Crypto::Hex::Encode(&u64val, sizeof(u64val));

/* encoded = "aaaaaaaaaaaaaaaa" */

char arr[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0x99, 0x00 };

encoded = Crypto::Hex::Encode(arr, sizeof(arr));

/* encoded = "aabbccdd9900" */
```
#### Crypto::Hex::Decode method

Decode HEX encoded data

```C++
#include <Crypto\Hex.hpp>

using namespace m4x1m1l14n;

std::string encoded = "4461746120746f2062652048455820656e636f646564";

std::string decoded = Crypto::Hex::Decode(encoded);

/* decoded = "Data to be HEX encoded" */
```

## Crypto::Base64 namespace
### Methods
#### Crypto::Base64::Encode method
#### Crypto::Base64::Decode method





