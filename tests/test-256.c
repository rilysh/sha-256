#include <stdio.h>

#include "sha-256.h"

int main(void)
{
	struct sha256_ctx ctx;

        const char *a = "Hello world";
	const char *b = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
		" Suspendisse nec gravida nibh. Etiam scelerisque nibh ut metus ultrices sodales.";
	int i;
	uint8_t hash[64] = {0};

        sha256_init(&ctx);
        sha256_update(&ctx, a, strlen(a));
        sha256_final(&ctx, hash);

        for (i = 0; i < SHA256_DIGEST_SIZE; i++)
                fprintf(stdout, "%02x", hash[i]);

	fputc('\n', stdout);

	sha256_init(&ctx);
        sha256_update(&ctx, b, strlen(b));
        sha256_final(&ctx, hash);

	for (i = 0; i < SHA256_DIGEST_SIZE; i++)
                fprintf(stdout, "%02x", hash[i]);

	fputc('\n', stdout);
}

