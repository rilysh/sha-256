#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <string.h>

/* See: https://datatracker.ietf.org/doc/html/rfc6234#section-5.1 */
#define ROTR(x, n)           (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)          (((x) & (y)) ^ ((~x) & (z)))
#define MAJ(x, y, z)         (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)             ((ROTR(x, 2)) ^ (ROTR(x, 13)) ^ (ROTR(x, 22)))
#define BSIG1(x)             ((ROTR(x, 6)) ^ (ROTR(x, 11)) ^ (ROTR(x, 25)))
#define SSIG0(x)             ((ROTR(x, 7)) ^ (ROTR(x, 18)) ^ (x >> 3))
#define SSIG1(x)             ((ROTR(x, 17)) ^ (ROTR(x, 19)) ^ (x >> 10))
#define SHA256_BLOCK_SIZE    64
#define SHA256_DIGEST_SIZE   (SHA256_BLOCK_SIZE - 32) /* size: 32 */

#ifdef __has_attribute
#  if __has_attribute(packed)
#    define PACKED    __attribute__((packed))
#  else
#    define PACKED
#  endif
#endif

#define asizeof(x)        (sizeof(x) / sizeof(x[0]))

struct sha256_ctx {
	uint32_t block[SHA256_BLOCK_SIZE];
	uint32_t state[SHA256_BLOCK_SIZE >> 3]; /* size: 8 */
	uint32_t blocks_used;
	uint64_t bits_used;
} PACKED;

/* Public functions */ 
void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const void *data, size_t sz);
void sha256_final(struct sha256_ctx *ctx, uint8_t *digest);

#endif /* SHA-256_H */
