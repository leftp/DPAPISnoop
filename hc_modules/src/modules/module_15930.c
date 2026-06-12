/**
 *
 * DPAPI CREDHIST entry (AES-256/SHA-512)
 *
 * Format:
 *   $credhist$*<rev>*<SID>*<hash_algo_hex>*<crypt_algo_hex>*<rounds>*<iv_hex>*<sha_len>*<nt_len>*<enc_hex>
 *
 * Accepted fields:
 *   hash_algo  = 0x800e  (CALG_SHA_512)
 *   crypt_algo = 0x6610  (CALG_AES_256)
 *   iv         = 16 bytes (PBKDF2 salt, 32 hex chars)
 *   enc        = 48 bytes (3 AES-256 blocks, 96 hex chars)
 *
 * Key derivation:
 *   sha1_pass  = SHA1( password.UTF16LE )
 *   enc_key    = HMAC-SHA1( sha1_pass, (SID + NUL).UTF16LE )
 *   derived    = PBKDF2-HMAC-SHA512( enc_key, iv, rounds, dklen=48 )
 *   aes_key    = derived[ 0..31]  (32 bytes, AES-256)
 *   cbc_iv     = derived[32..47]  (16 bytes)
 *   plaintext  = AES-256-CBC-decrypt( aes_key, cbc_iv, enc )
 *
 * Plaintext layout:
 *   sha1_prev(20) | ntlm_prev(16) | [4-null-pad on Win10+] | zero_pad(8 or 12)
 *   nt_len=16 on pre-Win10; nt_len=20 on Win10 20H2+ (NTLM(16) + 4 null padding bytes)
 *
 * Verification:
 *   plaintext[sha_len+nt_len .. 47] == b'\x00'
 *
 * References:
 *   CALG_AES_256 = 0x6610, appears on Windows 10 20H2+
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DPAPI_PW_MAX   = 127;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "DPAPI CREDHIST entry (AES-256)";
static const u64   KERN_TYPE      = 15930;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$credhist$*3*S-1-5-21-111111111-222222222-333333333-1001*0x800e*0x6610*8000*000102030405060708090a0b0c0d0e0f*20*16*9a318c41c7245533ca003993382c3905c7e1759e8165080afc0cc8e549d175870243b8459653f5724ac60d84698f492d";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_pw_max         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DPAPI_PW_MAX;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

/* esalt: parsed CREDHIST AES-256 entry */
typedef struct dpapi_credhist_aes
{
  u32 revision;
  u32 SID[32];          /* SID as UTF-16LE with trailing NUL, byte-swapped for GPU */
  u32 SID_len;          /* byte length including NUL = (ascii_len + 1) * 2 */
  u32 iv[4];            /* PBKDF2 salt (16 bytes), byte-swapped */
  u32 enc[12];          /* encrypted payload (48 bytes), byte-swapped */
  u32 sha_len;          /* always 20 */
  u32 nt_len;           /* 16 (pre-Win10) or 20 (Win10+ = NTLM(16) + 4 null bytes) */
} dpapi_credhist_aes_t;

/* tmp: PBKDF2-HMAC-SHA512 state — dklen=48 needs only 1 SHA-512 block */
typedef struct dpapimk_tmp_v2
{
  u64 ipad64[8];
  u64 opad64[8];
  u64 dgst64[8];
  u64 out64[8];
} dpapimk_tmp_v2_t;

static const char *SIGNATURE_CREDHIST = "$credhist$*";

/* ------------------------------------------------------------------ */

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (dpapimk_tmp_v2_t);
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (dpapi_credhist_aes_t);
}

/* ------------------------------------------------------------------ */

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  dpapi_credhist_aes_t *ch = (dpapi_credhist_aes_t *) esalt_buf;

  memset (ch, 0, sizeof (dpapi_credhist_aes_t));

  hc_token_t token;
  memset (&token, 0, sizeof (hc_token_t));

  /*
   * Tokens: 0          1     2      3            4            5        6    7         8         9
   *         signature  rev   SID    hash_algo    crypt_algo   rounds   iv   sha_len   nt_len    enc
   */

  token.token_cnt = 10;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_CREDHIST;

  /* token[0]: "$credhist$" */
  token.len[0]  = 11;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  /* token[1]: revision — 1 decimal digit */
  token.sep[1]  = '*';
  token.len[1]  = 1;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_DIGIT;

  /* token[2]: SID */
  token.sep[2]     = '*';
  token.len_min[2] = 10;
  token.len_max[2] = 60;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  /* token[3]: hash_algo e.g. 0x800e */
  token.sep[3]     = '*';
  token.len_min[3] = 4;
  token.len_max[3] = 8;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  /* token[4]: crypt_algo e.g. 0x6610 */
  token.sep[4]     = '*';
  token.len_min[4] = 4;
  token.len_max[4] = 8;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  /* token[5]: PBKDF2 iteration count */
  token.sep[5]     = '*';
  token.len_min[5] = 1;
  token.len_max[5] = 8;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  /* token[6]: iv — 32 hex chars (16 bytes, PBKDF2 salt) */
  token.sep[6]  = '*';
  token.len[6]  = 32;
  token.attr[6] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  /* token[7]: sha_len */
  token.sep[7]     = '*';
  token.len_min[7] = 1;
  token.len_max[7] = 3;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  /* token[8]: nt_len */
  token.sep[8]     = '*';
  token.len_min[8] = 1;
  token.len_max[8] = 3;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  /* token[9]: encrypted payload hex */
  token.len_min[9] = 16;
  token.len_max[9] = 256;
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc = input_tokenizer ((const u8 *) line_buf, line_len, &token);
  if (rc != PARSER_OK) return rc;

  const u8 *SID_pos        = token.buf[2];
  const u8 *hash_algo_pos  = token.buf[3];
  const u8 *crypt_algo_pos = token.buf[4];
  const u8 *rounds_pos     = token.buf[5];
  const u8 *iv_pos         = token.buf[6];
  const u8 *sha_len_pos    = token.buf[7];
  const u8 *nt_len_pos     = token.buf[8];
  const u8 *enc_pos        = token.buf[9];

  ch->revision = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  /* hash_algo: this module requires 0x800e (CALG_SHA_512) */
  const u32 hash_algo  = hc_strtoul ((const char *) hash_algo_pos,  NULL, 0);
  if (hash_algo != 0x800e) return PARSER_SALT_VALUE;

  /* crypt_algo: this module requires 0x6610 (CALG_AES_256) */
  const u32 crypt_algo = hc_strtoul ((const char *) crypt_algo_pos, NULL, 0);
  if (crypt_algo != 0x6610) return PARSER_SALT_VALUE;

  /* sha_len and nt_len */
  const u32 sha_len = hc_strtoul ((const char *) sha_len_pos, NULL, 10);
  const u32 nt_len  = hc_strtoul ((const char *) nt_len_pos,  NULL, 10);

  if (sha_len != 20) return PARSER_SALT_VALUE;
  if (nt_len != 16 && nt_len != 20) return PARSER_SALT_VALUE;

  ch->sha_len = sha_len;
  ch->nt_len  = nt_len;

  /* enc_len: (sha_len + nt_len) rounded up to AES block boundary (16 bytes) = 48 */
  const u32 plain_len    = sha_len + nt_len;                    /* 36 */
  const u32 enc_len      = plain_len + ((16 - (plain_len % 16)) % 16); /* 48 */
  const u32 enc_hex_len  = enc_len * 2;                         /* 96 */

  if ((u32) token.len[9] != enc_hex_len) return PARSER_SALT_LENGTH;

  /* Parse enc (byte-swap each u32 for GPU internal representation) */
  for (u32 i = 0; i < enc_len / 4; i++)
  {
    ch->enc[i] = hex_to_u32 (&enc_pos[i * 8]);
    ch->enc[i] = byte_swap_32 (ch->enc[i]);
  }

  /* Parse iv (16 bytes = 4 u32, byte-swapped) */
  ch->iv[0] = hex_to_u32 (&iv_pos[ 0]); ch->iv[0] = byte_swap_32 (ch->iv[0]);
  ch->iv[1] = hex_to_u32 (&iv_pos[ 8]); ch->iv[1] = byte_swap_32 (ch->iv[1]);
  ch->iv[2] = hex_to_u32 (&iv_pos[16]); ch->iv[2] = byte_swap_32 (ch->iv[2]);
  ch->iv[3] = hex_to_u32 (&iv_pos[24]); ch->iv[3] = byte_swap_32 (ch->iv[3]);

  /* Parse SID: encode as UTF-16LE with trailing NUL, byte-swap u32 blocks */
  const int SID_ascii_len = token.len[2];

  u8 SID_utf16le[128] = { 0 };

  for (int i = 0; i < SID_ascii_len; i++)
  {
    SID_utf16le[i * 2] = SID_pos[i];
  }

  ch->SID_len = (SID_ascii_len + 1) * 2;

  SID_utf16le[ch->SID_len] = 0x80;

  memcpy ((u8 *) ch->SID, SID_utf16le, sizeof (ch->SID));

  for (u32 i = 0; i < 32; i++)
  {
    ch->SID[i] = byte_swap_32 (ch->SID[i]);
  }

  digest[0] = ch->iv[0];
  digest[1] = ch->iv[1];
  digest[2] = ch->iv[2];
  digest[3] = ch->iv[3];

  salt->salt_buf[0] = ch->iv[0];
  salt->salt_buf[1] = ch->iv[1];
  salt->salt_buf[2] = ch->iv[2];
  salt->salt_buf[3] = ch->iv[3];
  salt->salt_len    = 16;

  const u32 rounds = hc_strtoul ((const char *) rounds_pos, NULL, 10);
  if (rounds < 1 || rounds > 2000000) return PARSER_SALT_VALUE;
  salt->salt_iter = rounds - 1;

  return PARSER_OK;
}

/* ------------------------------------------------------------------ */

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const dpapi_credhist_aes_t *ch = (const dpapi_credhist_aes_t *) esalt_buf;

  const u32 rounds = salt->salt_iter + 1;

  /* Reconstruct SID ASCII from UTF-16LE u32 array */
  u8 SID_tmp[256 + 1] = { 0 };

  for (u32 i = 0; i < ch->SID_len / 4; i++)
  {
    u8 hex8[8] = { 0 };
    u32_to_hex (byte_swap_32 (ch->SID[i]), hex8);

    for (u32 j = 0, k = 0; j < 8; j += 2, k++)
      SID_tmp[i * 4 + k] = hex_to_u8 (&hex8[j]);
  }

  SID_tmp[ch->SID_len] = 0;

  u8 SID[128] = { 0 };
  for (u32 i = 0, j = 0; j < ch->SID_len; i++, j += 2)
    SID[i] = SID_tmp[j];

  /* Reconstruct iv hex */
  u8 iv_hex[32 + 1] = { 0 };
  for (u32 i = 0; i < 4; i++)
    u32_to_hex (byte_swap_32 (ch->iv[i]), iv_hex + i * 8);

  /* Reconstruct enc hex (48 bytes) */
  u8 enc_hex[96 + 1] = { 0 };
  for (u32 i = 0; i < 12; i++)
    u32_to_hex (byte_swap_32 (ch->enc[i]), enc_hex + i * 8);

  const int line_len = snprintf (line_buf, line_size,
    "%s%u*%s*0x800e*0x6610*%u*%s*%u*%u*%s",
    SIGNATURE_CREDHIST,
    ch->revision,
    (const char *) SID,
    rounds,
    (const char *) iv_hex,
    ch->sha_len,
    ch->nt_len,
    (const char *) enc_hex);

  return line_len;
}

/* ------------------------------------------------------------------ */

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
