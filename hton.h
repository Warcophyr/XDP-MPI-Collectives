#ifndef HTON_H
#define HTON_H
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#endif
// 64‑bit version of htonl/ntohl
static inline uint64_t htonll(uint64_t x) {
// On little‑endian this swaps; on big‑endian this is a no‑op.
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return ((uint64_t)htonl(x & 0xFFFFFFFFULL) << 32) | (uint64_t)htonl(x >> 32);
#else
  return x;
#endif
}
#define ntohll(x) htonll(x)

typedef __uint128_t uint128_t;

static inline uint128_t hton128(uint128_t x) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  uint64_t high = (uint64_t)(x >> 64);
  uint64_t low = (uint64_t)(x & 0xFFFFFFFFFFFFFFFFULL);

  high = htonll(low); // Note the swap of high/low
  low = htonll(high);

  return ((uint128_t)high) << 64 | low;
#else
  return x;
#endif
}

#define ntoh128(x) hton128(x) // Same logic applies

// Convert host float to network order
static inline uint32_t htonf(float f) {
  uint32_t v;
  memcpy(&v, &f, sizeof(v)); // copy IEEE bits
  return htonl(v);           // byte‑swap as 32‑bit int
}

// Convert host double to network order
static inline uint64_t htond(double d) {
  uint64_t v;
  memcpy(&v, &d, sizeof(v));
  return htonll(v);
}

static inline uint64_t htonLd(long double d) {
  uint128_t v;
  memcpy(&v, &d, sizeof(v));
  return hton128(v);
}

// And the reverse:
static inline float ntohf(uint32_t v) {
  v = ntohl(v);
  float f;
  memcpy(&f, &v, sizeof(f));
  return f;
}

static inline double ntohd(uint64_t v) {
  v = htonll(v); // ntohll is same as htonll
  double d;
  memcpy(&d, &v, sizeof(d));
  return d;
}

static inline long double ntohLd(uint128_t v) {
  v = hton128(v);
  long double d;
  memcpy(&d, &v, sizeof(d));
  return d;
}

inline int generic_hton(void *out, const void *in, size_t element_size,
                        size_t count) {
  const char *input = (const char *)in;
  char *output = (char *)out;

  for (size_t i = 0; i < count; i++) {
    const void *src = input + (i * element_size);
    void *dest = output + (i * element_size);

    switch (element_size) {
    case 1: {
      // uint8_t temp;
      // memcpy(&temp, src, 1);
      // temp = htons(temp);
      // memcpy(dest, &temp, 1);
      memcpy(dest, src, 1);
      break;
    }
    case 2: {
      uint16_t temp;
      memcpy(&temp, src, 2);
      temp = htons(temp);
      memcpy(dest, &temp, 2);
      break;
    }
    case 4: {
      uint32_t temp;
      memcpy(&temp, src, 4);
      temp = htonl(temp);
      memcpy(dest, &temp, 4);
      break;
    }
    case 8: {
      uint64_t temp;
      memcpy(&temp, src, 8);
      temp = htonll(temp);
      memcpy(dest, &temp, 8);
      break;
    }
    case 16: {
      uint128_t temp;
      memcpy(&temp, src, 16);
      temp = hton128(temp);
      memcpy(dest, &temp, 16);
      break;
    }
    default:
      // Unsupported size
      return -1;
    }
  }
  return count;
}

#define generic_ntoh(out, in, element_size, count)                             \
  generic_hton(out, in, element_size, count)
