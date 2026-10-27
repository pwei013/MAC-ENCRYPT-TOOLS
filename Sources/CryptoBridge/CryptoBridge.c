#include "CryptoBridge.h"
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>
#include <string.h>
#include <limits.h>

/* A private library context never reads the user's openssl.cnf. Both providers
   are built into the static archive; no global provider settings are changed. */
extern int ossl_legacy_provider_init(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *,
                                    const OSSL_DISPATCH **, void **);
static OSSL_LIB_CTX *library = NULL;
static OSSL_PROVIDER *default_provider = NULL, *legacy_provider = NULL;

int cd_initialize(void) {
    library = OSSL_LIB_CTX_new();
    if (!library) return 0;
    if (!OSSL_PROVIDER_add_builtin(library, "legacy", ossl_legacy_provider_init)) return 0;
    default_provider = OSSL_PROVIDER_load(library, "default");
    legacy_provider = OSSL_PROVIDER_load(library, "legacy");
    return default_provider != NULL && legacy_provider != NULL;
}
const char *cd_version(void) { return OpenSSL_version(OPENSSL_VERSION); }
void cd_release(void *buffer, size_t length) { OPENSSL_clear_free(buffer, length); }

int cd_digest(const char *name, const uint8_t *input, size_t length,
              uint8_t **output, size_t *output_length) {
    ERR_clear_error();
    EVP_MD *md = EVP_MD_fetch(library, name, NULL);
    if (!md) return 0;
    unsigned char *result = OPENSSL_malloc(EVP_MD_get_size(md));
    unsigned int size = 0;
    int ok = result && EVP_Digest(input, length, result, &size, md, NULL);
    EVP_MD_free(md);
    if (!ok) { OPENSSL_free(result); ERR_clear_error(); return 0; }
    *output = result; *output_length = size; return 1;
}

int cd_cipher(const char *name, int encrypt, int padding,
              const uint8_t *key, size_t key_length,
              const uint8_t *iv, size_t iv_length,
              const uint8_t *input, size_t input_length,
              uint8_t **output, size_t *output_length) {
    ERR_clear_error();
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(library, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!cipher || !ctx || input_length > INT_MAX ||
        key_length != (size_t)EVP_CIPHER_get_key_length(cipher) ||
        iv_length != (size_t)EVP_CIPHER_get_iv_length(cipher)) {
        EVP_CIPHER_free(cipher); EVP_CIPHER_CTX_free(ctx); return 0;
    }
    size_t capacity = input_length + EVP_CIPHER_get_block_size(cipher);
    uint8_t *result = OPENSSL_malloc(capacity);
    int count = 0, last = 0;
    int ok = result && EVP_CipherInit_ex2(ctx, cipher, key, iv, encrypt, NULL) &&
        EVP_CIPHER_CTX_set_padding(ctx, padding) &&
        EVP_CipherUpdate(ctx, result, &count, input, (int)input_length) &&
        EVP_CipherFinal_ex(ctx, result + count, &last);
    EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(cipher); ERR_clear_error();
    if (!ok) { OPENSSL_clear_free(result, capacity); return 0; }
    *output = result; *output_length = (size_t)(count + last); return 1;
}

static EVP_PKEY *read_key(const char *pem, int is_private) {
    if (!pem || strlen(pem) > INT_MAX) return NULL;
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return NULL;
    /* No password callback: encrypted PEM never triggers a terminal prompt. */
    EVP_PKEY *key = is_private
        ? PEM_read_bio_PrivateKey_ex(bio, NULL, NULL, "", library, NULL)
        : PEM_read_bio_PUBKEY_ex(bio, NULL, NULL, "", library, NULL);
    BIO_free(bio); return key;
}

int cd_validate_key(const char *algorithm, const char *pem, int is_private) {
    ERR_clear_error();
    EVP_PKEY *key = read_key(pem, is_private);
    int ok = key && EVP_PKEY_is_a(key, algorithm);
    if (ok) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(library, key, NULL);
        ok = ctx && (is_private ? EVP_PKEY_pairwise_check(ctx) : EVP_PKEY_public_check(ctx)) > 0;
        EVP_PKEY_CTX_free(ctx);
    }
    EVP_PKEY_free(key); ERR_clear_error(); return ok;
}

int cd_validate_pair(const char *public_pem, const char *private_pem) {
    EVP_PKEY *pub = read_key(public_pem, 0), *priv = read_key(private_pem, 1);
    int ok = pub && priv && EVP_PKEY_eq(pub, priv) == 1;
    EVP_PKEY_free(pub); EVP_PKEY_free(priv); ERR_clear_error(); return ok;
}

static int copy_bio(BIO *bio, char **result, size_t *length) {
    char *bytes = NULL; long size = BIO_get_mem_data(bio, &bytes);
    if (size <= 0) return 0;
    *result = OPENSSL_malloc((size_t)size + 1);
    if (!*result) return 0;
    memcpy(*result, bytes, size); (*result)[size] = 0;
    *length = (size_t)size; return 1;
}

int cd_sm2_import(const uint8_t *bytes, size_t length, int is_private,
                  char **pem, size_t *pem_length) {
    ERR_clear_error();
    if (!bytes || (is_private ? length != 32 : length != 65 || bytes[0] != 4)) return 0;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    EC_POINT *point = group ? EC_POINT_new(group) : NULL;
    BIGNUM *scalar = is_private ? BN_bin2bn(bytes, (int)length, NULL) : NULL;
    BIGNUM *order = BN_new();
    BN_CTX *bnctx = BN_CTX_new();
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(library, "SM2", NULL);
    EVP_PKEY *key = NULL;
    BIO *bio = BIO_new(BIO_s_mem());
    unsigned char public_bytes[65];
    int ok = group && point && order && bnctx && builder && ctx && bio;
    if (ok && is_private) {
        ok = scalar && !BN_is_zero(scalar) && EC_GROUP_get_order(group, order, bnctx) &&
            BN_cmp(scalar, order) < 0 && EC_POINT_mul(group, point, scalar, NULL, NULL, bnctx);
    } else if (ok) {
        ok = EC_POINT_oct2point(group, point, bytes, length, bnctx) &&
            EC_POINT_is_on_curve(group, point, bnctx) == 1 && !EC_POINT_is_at_infinity(group, point);
    }
    if (ok) ok = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                   public_bytes, sizeof(public_bytes), bnctx) == 65 &&
        OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0) &&
        OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, public_bytes, 65);
    if (ok && is_private) ok = OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, scalar);
    if (ok) {
        params = OSSL_PARAM_BLD_to_param(builder);
        ok = params && EVP_PKEY_fromdata_init(ctx) > 0 &&
            EVP_PKEY_fromdata(ctx, &key, is_private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) > 0;
    }
    if (ok) ok = (is_private ? PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL)
                             : PEM_write_bio_PUBKEY(bio, key)) && copy_bio(bio, pem, pem_length);
    BIO_free(bio); EVP_PKEY_free(key); EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params); OSSL_PARAM_BLD_free(builder);
    BN_clear_free(scalar); BN_free(order); BN_CTX_free(bnctx);
    EC_POINT_free(point); EC_GROUP_free(group); ERR_clear_error(); return ok;
}

int cd_sm2_export(const char *pem, int is_private, uint8_t **bytes, size_t *length) {
    ERR_clear_error();
    EVP_PKEY *key = read_key(pem, is_private);
    BIGNUM *scalar = NULL;
    uint8_t *result = NULL;
    size_t size = is_private ? 32 : 65;
    int ok = key && EVP_PKEY_is_a(key, "SM2");
    if (ok) { result = OPENSSL_malloc(size); ok = result != NULL; }
    if (ok && is_private) {
        ok = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &scalar) && BN_bn2binpad(scalar, result, 32) == 32;
    } else if (ok) {
        unsigned char encoded[133]; size_t encoded_length = 0;
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
        EC_POINT *point = group ? EC_POINT_new(group) : NULL;
        ok = point && EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, encoded, sizeof(encoded), &encoded_length) &&
            EC_POINT_oct2point(group, point, encoded, encoded_length, NULL) &&
            EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, result, size, NULL) == size;
        EC_POINT_free(point); EC_GROUP_free(group);
    }
    BN_clear_free(scalar); EVP_PKEY_free(key); ERR_clear_error();
    if (!ok) { OPENSSL_clear_free(result, size); return 0; }
    *bytes = result; *length = size; return 1;
}

int cd_rsa_component(const char *pem, int is_private, int component,
                     uint8_t **bytes, size_t *length) {
    static const char *names[] = { OSSL_PKEY_PARAM_RSA_N, OSSL_PKEY_PARAM_RSA_E,
        OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PKEY_PARAM_RSA_FACTOR2,
        OSSL_PKEY_PARAM_RSA_EXPONENT1, OSSL_PKEY_PARAM_RSA_EXPONENT2,
        OSSL_PKEY_PARAM_RSA_COEFFICIENT1, OSSL_PKEY_PARAM_RSA_D };
    if (component < 0 || component > (is_private ? 7 : 1)) return 0;
    ERR_clear_error();
    EVP_PKEY *key = read_key(pem, is_private);
    BIGNUM *number = NULL, *modulus = NULL;
    int ok = key && EVP_PKEY_is_a(key, "RSA") && EVP_PKEY_get_bn_param(key, names[component], &number) &&
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &modulus);
    int size = ok ? BN_num_bytes(modulus) : 0;
    if (ok && component == 1) size = BN_num_bytes(number);
    else if (ok && component >= 2 && component <= 6) size = (size + 1) / 2;
    uint8_t *result = ok && size > 0 ? OPENSSL_malloc(size) : NULL;
    ok = result && BN_bn2binpad(number, result, size) == size;
    BN_clear_free(number); BN_free(modulus); EVP_PKEY_free(key); ERR_clear_error();
    if (!ok) { OPENSSL_clear_free(result, size); return 0; }
    *bytes = result; *length = (size_t)size; return 1;
}

int cd_generate(const char *algorithm, int bits, char **public_pem,
                size_t *public_length, char **private_pem, size_t *private_length) {
    ERR_clear_error();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(library, algorithm, NULL);
    EVP_PKEY *key = NULL;
    BIO *pub = BIO_new(BIO_s_mem()), *priv = BIO_new(BIO_s_mem());
    int ok = ctx && pub && priv && EVP_PKEY_keygen_init(ctx) > 0;
    if (ok && strcmp(algorithm, "RSA") == 0)
        ok = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) > 0;
    ok = ok && EVP_PKEY_generate(ctx, &key) > 0 &&
        PEM_write_bio_PUBKEY(pub, key) &&
        PEM_write_bio_PrivateKey(priv, key, NULL, NULL, 0, NULL, NULL) &&
        copy_bio(pub, public_pem, public_length) && copy_bio(priv, private_pem, private_length);
    BIO_free(pub); BIO_free(priv); EVP_PKEY_free(key); EVP_PKEY_CTX_free(ctx);
    ERR_clear_error(); return ok;
}

int cd_asymmetric(const char *algorithm, int encrypt, int oaep,
                 const char *pem, const uint8_t *input, size_t input_length,
                 uint8_t **output, size_t *output_length) {
    ERR_clear_error();
    EVP_PKEY *key = read_key(pem, !encrypt);
    EVP_PKEY_CTX *ctx = key ? EVP_PKEY_CTX_new_from_pkey(library, key, NULL) : NULL;
    int ok = ctx && EVP_PKEY_is_a(key, algorithm);
    if (ok) ok = (encrypt ? EVP_PKEY_encrypt_init(ctx) : EVP_PKEY_decrypt_init(ctx)) > 0;
    if (ok && strcmp(algorithm, "RSA") == 0) {
        ok = EVP_PKEY_CTX_set_rsa_padding(ctx, oaep ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING) > 0;
        if (ok && oaep) ok = EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, "SHA256", NULL) > 0 &&
            EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256", NULL) > 0;
        if (ok && !oaep) {
            unsigned int reject = 0;
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, &reject),
                OSSL_PARAM_construct_end()
            };
            ok = EVP_PKEY_CTX_set_params(ctx, params) > 0;
        }
        if (ok && encrypt) {
            int maximum = EVP_PKEY_get_size(key) - (oaep ? 66 : 11);
            if (maximum < 0 || input_length > (size_t)maximum) ok = 0;
        }
    }
    size_t length = 0;
    if (ok) ok = (encrypt ? EVP_PKEY_encrypt(ctx, NULL, &length, input, input_length)
                          : EVP_PKEY_decrypt(ctx, NULL, &length, input, input_length)) > 0;
    uint8_t *result = ok ? OPENSSL_malloc(length) : NULL;
    size_t capacity = length;
    if (ok) ok = result && (encrypt ? EVP_PKEY_encrypt(ctx, result, &length, input, input_length)
                                    : EVP_PKEY_decrypt(ctx, result, &length, input, input_length)) > 0;
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(key); ERR_clear_error();
    if (!ok) { OPENSSL_clear_free(result, capacity); return 0; }
    *output = result; *output_length = length; return 1;
}
