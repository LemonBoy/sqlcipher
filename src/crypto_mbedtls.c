#ifdef SQLITE_HAS_CODEC
#ifdef SQLCIPHER_CRYPTO_MBEDTLS
#include "sqliteInt.h"
#include "crypto.h"
#include "sqlcipher.h"

#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha1.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/version.h"
#include "mbedtls/pkcs5.h"

#define AES256_CBC_KEY_SIZE   32
#define AES256_CBC_IV_SIZE    16
#define HMAC_SHA1_DIGEST_SIZE 20

static unsigned int mbedtls_init = 0;
static unsigned int mbedtls_ref_count = 0;

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context rng_ctx;
static mbedtls_md_info_t *hash_info = NULL;

static int sqlcipher_mbedtls_add_random(void *ctx, void *buffer, int length) {
  printf("%s\n", __FUNCTION__);

  mbedtls_ctr_drbg_update(&rng_ctx, buffer, length);

  return SQLITE_OK;
}

static int sqlcipher_mbedtls_activate(void *ctx) {
  printf("%s\n", __FUNCTION__);

  if (mbedtls_init == 0) {
    mbedtls_entropy_init(&entropy_ctx);
    mbedtls_ctr_drbg_init(&rng_ctx);
    // Initialize the RNG using the available entropy pool
    if (mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &entropy_ctx,
                              MBEDTLS_VERSION_STRING_FULL,
                              strlen(MBEDTLS_VERSION_STRING_FULL))) {
      printf("seeding went wrong\n");
      return SQLITE_ERROR;
    }
    hash_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (hash_info == NULL) {
      printf("Could not obtain the SHA1 info\n");
      return SQLITE_ERROR;
    }
    mbedtls_init = 1;
  }

  mbedtls_ref_count++;

  return SQLITE_OK;
}

static int sqlcipher_mbedtls_deactivate(void *ctx) {
  printf("%s\n", __FUNCTION__);

  mbedtls_ref_count--;

  if (mbedtls_ref_count == 0) {
    mbedtls_ctr_drbg_free(&rng_ctx);
    mbedtls_entropy_free(&entropy_ctx);
    mbedtls_init = 0;
    hash_info = NULL;
  }

  return SQLITE_OK;
}

static const char* sqlcipher_mbedtls_get_provider_name(void *ctx) {
  return "mbed TLS";
}

static const char* sqlcipher_mbedtls_get_provider_version(void *ctx) {
  return MBEDTLS_VERSION_STRING;
}

/* generate a defined number of random bytes */
static int sqlcipher_mbedtls_random (void *ctx, void *buffer, int length) {
  printf("%s %d\n", __FUNCTION__, length);

  if (mbedtls_ctr_drbg_random(&rng_ctx, buffer, length)) {
    printf("random() failed\n");
    return SQLITE_ERROR;
  }

  return SQLITE_OK;
}

static int sqlcipher_mbedtls_hmac(void *ctx, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  printf("%s\n", __FUNCTION__);

  mbedtls_md_context_t hctx;

  mbedtls_md_init(&hctx);
  mbedtls_md_setup(&hctx, hash_info, 1);

  mbedtls_md_hmac_starts(&hctx, hmac_key, key_sz);
  mbedtls_md_hmac_update(&hctx, in, in_sz);
  mbedtls_md_hmac_update(&hctx, in2, in2_sz);
  mbedtls_md_hmac_finish(&hctx, out);

  mbedtls_md_free(&hctx);

  return SQLITE_OK; 
}

static int sqlcipher_mbedtls_kdf(void *ctx, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  printf("%s\n", __FUNCTION__);

  mbedtls_md_context_t hctx;

  mbedtls_md_init(&hctx);
  mbedtls_md_setup(&hctx, hash_info, 1);

  if (mbedtls_pkcs5_pbkdf2_hmac(&hctx, pass, pass_sz, salt, salt_sz, workfactor,
                                key_sz, key)) {
    printf("pbkdf2() failed\n");
    return SQLITE_ERROR;
  }

  mbedtls_md_free(&hctx);

  return SQLITE_OK; 
}

static int sqlcipher_mbedtls_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  mbedtls_aes_context actx;
  int mbedtls_mode;

  printf("%s %d %d\n", __FUNCTION__, mode, key_sz);

  mbedtls_aes_init(&actx);

  if (mode == CIPHER_ENCRYPT) {
    mbedtls_mode = MBEDTLS_AES_ENCRYPT;
    if (mbedtls_aes_setkey_enc(&actx, key, 8 * key_sz)) {
      printf("setkey_enc() failed\n");
      return SQLITE_ERROR;
    }
  } else {
    mbedtls_mode = MBEDTLS_AES_DECRYPT;
    if (mbedtls_aes_setkey_dec(&actx, key, 8 * key_sz)) {
      printf("setkey_dec() failed\n");
      return SQLITE_ERROR;
    }
  }

  unsigned char old_iv[AES256_CBC_IV_SIZE];
  memcpy(old_iv, iv, AES256_CBC_IV_SIZE);

  if (mbedtls_aes_crypt_cbc(&actx, mbedtls_mode, in_sz, iv, in, out)) {
    printf("crypt_cbc() failed\n");
    return SQLITE_ERROR;
  }

  memcpy(iv, old_iv, AES256_CBC_IV_SIZE);

  mbedtls_aes_free(&actx);
  return SQLITE_OK; 
}

static int sqlcipher_mbedtls_set_cipher(void *ctx, const char *cipher_name) {
  return strcmp(cipher_name, "aes-256-cbc") ? SQLITE_ERROR : SQLITE_OK;
}

static const char* sqlcipher_mbedtls_get_cipher(void *ctx) {
  return "aes-256-cbc";
}

static int sqlcipher_mbedtls_get_key_sz(void *ctx) {
  return AES256_CBC_KEY_SIZE;
}

static int sqlcipher_mbedtls_get_iv_sz(void *ctx) {
  return AES256_CBC_IV_SIZE;
}

static int sqlcipher_mbedtls_get_block_sz(void *ctx) {
  return 16;
}

static int sqlcipher_mbedtls_get_hmac_sz(void *ctx) {
  assert(hash_info);
  return HMAC_SHA1_DIGEST_SIZE;
}

static int sqlcipher_mbedtls_ctx_copy(void *target_ctx, void *source_ctx) {
  return SQLITE_OK;
}

static int sqlcipher_mbedtls_ctx_cmp(void *c1, void *c2) {
  return 1;
}

static int sqlcipher_mbedtls_ctx_init(void **ctx) {
  printf("%s\n", __FUNCTION__);
  sqlcipher_mbedtls_activate(NULL);
  return SQLITE_OK;
}

static int sqlcipher_mbedtls_ctx_free(void **ctx) {
  printf("%s\n", __FUNCTION__);
  sqlcipher_mbedtls_deactivate(NULL);
  return SQLITE_OK;
}

static int sqlcipher_mbedtls_fips_status(void *ctx) {
  return 0;
}

int sqlcipher_mbedtls_setup(sqlcipher_provider *p) {
  p->activate = sqlcipher_mbedtls_activate;  
  p->deactivate = sqlcipher_mbedtls_deactivate;
  p->get_provider_name = sqlcipher_mbedtls_get_provider_name;
  p->random = sqlcipher_mbedtls_random;
  p->hmac = sqlcipher_mbedtls_hmac;
  p->kdf = sqlcipher_mbedtls_kdf;
  p->cipher = sqlcipher_mbedtls_cipher;
  p->set_cipher = sqlcipher_mbedtls_set_cipher;
  p->get_cipher = sqlcipher_mbedtls_get_cipher;
  p->get_key_sz = sqlcipher_mbedtls_get_key_sz;
  p->get_iv_sz = sqlcipher_mbedtls_get_iv_sz;
  p->get_block_sz = sqlcipher_mbedtls_get_block_sz;
  p->get_hmac_sz = sqlcipher_mbedtls_get_hmac_sz;
  p->ctx_copy = sqlcipher_mbedtls_ctx_copy;
  p->ctx_cmp = sqlcipher_mbedtls_ctx_cmp;
  p->ctx_init = sqlcipher_mbedtls_ctx_init;
  p->ctx_free = sqlcipher_mbedtls_ctx_free;
  p->add_random = sqlcipher_mbedtls_add_random;
  p->fips_status = sqlcipher_mbedtls_fips_status;
  p->get_provider_version = sqlcipher_mbedtls_get_provider_version;
  return SQLITE_OK;
}


#endif
#endif
/* END SQLCIPHER */
