#include "sha-224.h"

/* Swap the bytes */
#define prep_stage_zero_expand(i, l0, l1, l2, l3)	   \
	w[i] = ((ctx->block[l0] << 24) |		   \
		(ctx->block[l1] << 16) |		   \
		(ctx->block[l2] << 8) |			   \
		(ctx->block[l3]))

/* See: https://datatracker.ietf.org/doc/html/rfc6234#section-5.1 */
static const uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void sha224_init(struct sha224_ctx *ctx)
{
	ctx->state[0] = 0xc1059ed8;
	ctx->state[1] = 0x367cd507;
	ctx->state[2] = 0x3070dd17;
	ctx->state[3] = 0xf70e5939;
	ctx->state[4] = 0xffc00b31;
	ctx->state[5] = 0x68581511;
	ctx->state[6] = 0x64f98fa7;
	ctx->state[7] = 0xbefa4fa4;

	ctx->bits_used = ctx->blocks_used = 0;
}

/*
  This section implements message processing.
  See: https://datatracker.ietf.org/doc/html/rfc6234#section-6.2

  Note: Ignore this, "For SHA-224, this is the concatenation of H(N)0,
  H(N)1, through H(N)6."
*/
static void sha224_process(struct sha224_ctx *ctx)
{
	uint32_t a, b, c, d, e, f, g, h, i, t1, t2, w[64];

	prep_stage_zero_expand(0, 0, 1, 2, 3);
	prep_stage_zero_expand(1, 4, 5, 6, 7);
	prep_stage_zero_expand(2, 8, 9, 10, 11);
	prep_stage_zero_expand(3, 12, 13, 14, 15);
	prep_stage_zero_expand(4, 16, 17, 18, 19);
	prep_stage_zero_expand(5, 20, 21, 22, 23);
	prep_stage_zero_expand(6, 24, 25, 26, 27);
	prep_stage_zero_expand(7, 28, 29, 30, 31);
	prep_stage_zero_expand(8, 32, 33, 34, 35);
	prep_stage_zero_expand(9, 36, 37, 38, 39);
	prep_stage_zero_expand(10, 40, 41, 42, 43);
	prep_stage_zero_expand(11, 44, 45, 46, 47);
	prep_stage_zero_expand(12, 48, 49, 50, 51);
	prep_stage_zero_expand(13, 52, 53, 54, 55);
	prep_stage_zero_expand(14, 56, 57, 58, 59);
	prep_stage_zero_expand(15, 60, 61, 62, 63);

	for (i = 16; i < 64; i++)
		w[i] = (SSIG1(w[i - 2]) + w[i - 7] +
			SSIG0(w[i - 15]) + w[i - 16]);

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; i++) {
		t1 = h + BSIG1(e) + CH(e, f, g) + k[i] + w[i];
		t2 = BSIG0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2; 
	}

        ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha224_update(struct sha224_ctx *ctx, const void *data, size_t sz)
{
	const unsigned char *p = (const unsigned char *)data;
        size_t i;

	for (i = 0; i < sz; i++) {
	        ctx->block[ctx->blocks_used++] = p[i];
		if (ctx->blocks_used >= 64) {
			sha224_process(ctx);
			ctx->blocks_used = 0;
			ctx->bits_used += 512;
		}
	}
}

void sha224_final(struct sha224_ctx *ctx, uint8_t *digest)
{
	uint32_t i;

	i = ctx->blocks_used;
	if (ctx->blocks_used < 56) {
	        ctx->block[i++] = 0x80;
	        while (i < 56)
			ctx->block[i++] = 0;
        } else {
		ctx->block[i++] = 0x80;
	        while (i < 64)
			ctx->block[i++] = 0;

		sha224_process(ctx);
	}

	/* Add the last padding (big-endian) */
        ctx->bits_used += ctx->blocks_used << 3;
	ctx->block[asizeof(ctx->block) - 1] = (uint32_t)(ctx->bits_used);
	ctx->block[asizeof(ctx->block) - 2] = (uint32_t)(ctx->bits_used >> 8);
	ctx->block[asizeof(ctx->block) - 3] = (uint32_t)(ctx->bits_used >> 16);
	ctx->block[asizeof(ctx->block) - 4] = (uint32_t)(ctx->bits_used >> 24);
	ctx->block[asizeof(ctx->block) - 5] = (uint32_t)(ctx->bits_used >> 32);
	ctx->block[asizeof(ctx->block) - 6] = (uint32_t)(ctx->bits_used >> 40);
	ctx->block[asizeof(ctx->block) - 7] = (uint32_t)(ctx->bits_used >> 48);
	ctx->block[asizeof(ctx->block) - 8] = (uint32_t)(ctx->bits_used >> 56);

	sha224_process(ctx);
	memset(ctx->block, '\0', sizeof(ctx->block));

	/*
	  Swap the bytes. This may get converted to a bswap
	  instruction on modern x86-64 CPUs.
	*/
	for (i = 0; i < 8; i++) {
		*digest++ = (uint8_t)(ctx->state[i] >> 24);
		*digest++ = (uint8_t)(ctx->state[i] >> 16);
		*digest++ = (uint8_t)(ctx->state[i] >> 8);
		*digest++ = (uint8_t)(ctx->state[i]);
	}

	/* Clear all artifacts */
	memset(ctx, '\0', sizeof(*ctx));
}
