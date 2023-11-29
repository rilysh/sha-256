#include <stdio.h>
#include <stdlib.h>

#include "sha-224.h"

int main(void)
{
        struct sha224_ctx ctx;

        const char *a = "Hello world";
	const char *b = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
		" Suspendisse nec gravida nibh. Etiam scelerisque nibh ut metus ultrices sodales.";
	int i;
	uint8_t hash[64] = {0};

        sha224_init(&ctx);
        sha224_update(&ctx, a, strlen(a));
        sha224_final(&ctx, hash);

        for (i = 0; i < SHA224_DIGEST_SIZE; i++)
                fprintf(stdout, "%02x", hash[i]);

	fputc('\n', stdout);

	sha224_init(&ctx);
        sha224_update(&ctx, b, strlen(b));
        sha224_final(&ctx, hash);

	for (i = 0; i < SHA224_DIGEST_SIZE; i++)
                fprintf(stdout, "%02x", hash[i]);

	fputc('\n', stdout);
}
