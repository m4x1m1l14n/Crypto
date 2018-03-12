# Crypto
C++ wrappers for Windows Crypto &amp; Crypto Next Generation API

## Crypto::Random namespace
### Methods
#### Crypto::Random::Generate method
Generating random basic data types

```C++
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
size_t arrlen = 32;

std::string randarr = Crypto::Random::GenerateArray(arrlen);
```
