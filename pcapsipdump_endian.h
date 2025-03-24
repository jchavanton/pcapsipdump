// detect target system endianness

#if sparc
  #define _BIG_ENDIAN 1
#else
  #include <sys/param.h>
#endif

#if !(__BYTE_ORDER == __LITTLE_ENDIAN) && \
    !(__BYTE_ORDER == __BIG_ENDIAN)
  #if defined(BYTE_ORDER) && \
      defined(LITTLE_ENDIAN) && \
      defined(BIG_ENDIAN) && \
      ((BYTE_ORDER == LITTLE_ENDIAN) || \
       (BYTE_ORDER == BIG_ENDIAN))
    #define __LITTLE_ENDIAN LITTLE_ENDIAN
    #define __BIG_ENDIAN    BIG_ENDIAN
    #define __BYTE_ORDER    BYTE_ORDER
  #elif defined(_BYTE_ORDER) && \
      defined(_LITTLE_ENDIAN) && \
      defined(_BIG_ENDIAN) && \
      ((_BYTE_ORDER == _LITTLE_ENDIAN) || \
       (_BYTE_ORDER == _BIG_ENDIAN))
    #define __LITTLE_ENDIAN _LITTLE_ENDIAN
    #define __BIG_ENDIAN    _BIG_ENDIAN
    #define __BYTE_ORDER    _BYTE_ORDER
  #elif !defined(_BYTE_ORDER) && defined(_LITTLE_ENDIAN)
    #define __LITTLE_ENDIAN 1234
    #define __BIG_ENDIAN    4321
    #define __BYTE_ORDER    4321
  #elif !defined(_BYTE_ORDER) && defined(_BIG_ENDIAN)
    #define __LITTLE_ENDIAN 1234
    #define __BIG_ENDIAN    4321
    #define __BYTE_ORDER    1234
  #else
    #error Unable to detect target system endianness
  #endif
#endif

#define CONST_BSWAP16(x)     ((uint16_t)(                        \
                             (((uint16_t)(x) >> 8) & 0x00FF)   | \
                             (((uint16_t)(x) << 8) & 0xFF00)))

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
  #define HTONS(x) CONST_BSWAP16(x)
#else
  #define HTONS(x) (x)
#endif
