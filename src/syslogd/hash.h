#ifndef SYSLOGD_HASH_H_
#define SYSLOGD_HASH_H_

#include "sha256.h"

/* A suitably aligned type for stack allocations of hash contexts. */
union hash_ctx {
	platform_SHA256_CTX sha256;
};
typedef union hash_ctx hash_ctx_t;

#ifdef USE_CHECKSUMS

/* The length in bytes and in hex digits (SHA-256 value). */
#define HASH_RAWSZ 32
#define HASH_HEXSZ (2 * HASH_RAWSZ)

#define HASH_NAME   "sha256"
#define HASH_NAMESZ sizeof(HASH_NAME) - 1

#define EMPTY_HASH_LITERAL \
	HASH_NAME ":e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

static inline void hash_init(hash_ctx_t *ctx)
{
	platform_SHA256_Init(&ctx->sha256);
}

static inline void hash_update(hash_ctx_t *ctx, const void *data, size_t len)
{
	platform_SHA256_Update(&ctx->sha256, data, len);
}

static inline void hash_final(unsigned char *hash, hash_ctx_t *ctx)
{
	platform_SHA256_Final(hash, &ctx->sha256);
}

#else /* USE_CHECKSUMS */

#define HASH_RAWSZ 0
#define HASH_HEXSZ 0

#define HASH_NAME   ""
#define HASH_NAMESZ 0

#define EMPTY_HASH_LITERAL ""

static inline void hash_init(hash_ctx_t *ctx)
{
	return;
}

static inline void hash_update(hash_ctx_t *ctx, const void *in, size_t len)
{
	return;
}

static inline void hash_final(unsigned char *hash, hash_ctx_t *ctx)
{
	return;
}

#endif /* USE_CHECKSUMS */
#endif
