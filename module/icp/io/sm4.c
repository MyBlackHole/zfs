// SPDX-License-Identifier: CDDL-1.0
#include <sys/zfs_context.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/icp.h>
#include <modes/modes.h>
#include <aes/aes_impl.h>
#include <sm4/sm4_impl.h>
#include <modes/gcm_impl.h>

static const crypto_mech_info_t sm4_mech_info_tab[] = {
	{SUN_CKM_SM4_GCM, SM4_GCM_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_DECRYPT_ATOMIC},
};

static int sm4_common_init_ctx(void *, crypto_spi_ctx_template_t *,
    crypto_mechanism_t *, crypto_key_t *, int, boolean_t);

static int sm4_encrypt_atomic(crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t);

static int sm4_decrypt_atomic(crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t);

static int
sm4_encrypt_contiguous_blocks(void *ctx, char *data, size_t length,
    crypto_data_t *out)
{
	aes_ctx_t *sm4_ctx = ctx;
	int rv;

	if (sm4_ctx->ac_flags & GCM_MODE) {
		rv = gcm_mode_encrypt_contiguous_blocks(ctx, data, length,
		    out, SM4_BLOCK_LEN, sm4_encrypt_block, aes_copy_block,
		    aes_xor_block);
	} else
		__builtin_unreachable();
	return (rv);
}

static int
sm4_decrypt_contiguous_blocks(void *ctx, char *data, size_t length,
    crypto_data_t *out)
{
	aes_ctx_t *sm4_ctx = ctx;
	int rv;

	if (sm4_ctx->ac_flags & GCM_MODE) {
		rv = gcm_mode_decrypt_contiguous_blocks(ctx, data, length,
		    out, SM4_BLOCK_LEN, sm4_encrypt_block, aes_copy_block,
		    aes_xor_block);
	} else
		__builtin_unreachable();
	return (rv);
}

static const crypto_cipher_ops_t sm4_cipher_ops = {
	.encrypt_atomic = sm4_encrypt_atomic,
	.decrypt_atomic = sm4_decrypt_atomic
};

static int sm4_create_ctx_template(crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t *, size_t *);
static int sm4_free_context(crypto_ctx_t *);

static const crypto_ctx_ops_t sm4_ctx_ops = {
	.create_ctx_template = sm4_create_ctx_template,
	.free_context = sm4_free_context
};

static const crypto_ops_t sm4_crypto_ops = {
	&sm4_cipher_ops,
	NULL,
	&sm4_ctx_ops,
};

static const crypto_provider_info_t sm4_prov_info = {
	"SM4 Software Provider",
	&sm4_crypto_ops,
	sizeof (sm4_mech_info_tab) / sizeof (crypto_mech_info_t),
	sm4_mech_info_tab
};

static crypto_kcf_provider_handle_t sm4_prov_handle = 0;

int
sm4_mod_init(void)
{
	/* Register with KCF */
	if (crypto_register_provider(&sm4_prov_info, &sm4_prov_handle))
		return (EACCES);

	return (0);
}

int
sm4_mod_fini(void)
{
	if (sm4_prov_handle != 0) {
		if (crypto_unregister_provider(sm4_prov_handle))
			return (EBUSY);
		sm4_prov_handle = 0;
	}

	return (0);
}

static int
init_keysched(crypto_key_t *key, void *newbie)
{
	if (key->ck_length != SM4_KEY_BITS)
		return (CRYPTO_KEY_SIZE_RANGE);

	sm4_init_keysched(key->ck_data, newbie);
	return (CRYPTO_SUCCESS);
}

static int
sm4_create_ctx_template(crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *tmpl, size_t *tmpl_size)
{
	void *keysched;
	size_t size;
	int rv;

	if (mechanism->cm_type != SM4_GCM_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	if ((keysched = sm4_alloc_keysched(&size, KM_SLEEP)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	if ((rv = init_keysched(key, keysched)) != CRYPTO_SUCCESS) {
		memset(keysched, 0, size);
		kmem_free(keysched, size);
		return (rv);
	}

	*tmpl = keysched;
	*tmpl_size = size;

	return (CRYPTO_SUCCESS);
}

static int
sm4_free_context(crypto_ctx_t *ctx)
{
	void *sm4_ctx = ctx->cc_provider_private;

	if (sm4_ctx != NULL) {
		crypto_free_mode_ctx(sm4_ctx);
		ctx->cc_provider_private = NULL;
	}

	return (CRYPTO_SUCCESS);
}

static int
sm4_common_init_ctx(void *sm4_ctx, crypto_spi_ctx_template_t *template,
    crypto_mechanism_t *mechanism, crypto_key_t *key, int kmflag,
    boolean_t is_encrypt_init)
{
	/* is_encrypt_init is used by CCM; SM4 only supports GCM */
	(void)is_encrypt_init;
	int rv = CRYPTO_SUCCESS;
	void *keysched;
	size_t size = 0;

	if (template == NULL) {
		if ((keysched = sm4_alloc_keysched(&size, kmflag)) == NULL)
			return (CRYPTO_HOST_MEMORY);
		if ((rv = init_keysched(key, keysched)) != CRYPTO_SUCCESS) {
			kmem_free(keysched, size);
			return (rv);
		}
		((aes_ctx_t *)sm4_ctx)->ac_flags |= PROVIDER_OWNS_KEY_SCHEDULE;
		((aes_ctx_t *)sm4_ctx)->ac_keysched_len = size;
	} else {
		keysched = template;
	}
	((aes_ctx_t *)sm4_ctx)->ac_keysched = keysched;

	switch (mechanism->cm_type) {
	case SM4_GCM_MECH_INFO_TYPE:
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_GCM_PARAMS))
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		/* SM4 must use generic GCM (non-AVX) to avoid type confusion
		 * in gcm_init_ctx() which casts gcm_keysched as aes_key_t */
		((aes_ctx_t *)sm4_ctx)->ac_flags |= GCM_USE_GENERIC;
		rv = gcm_init_ctx((gcm_ctx_t *)sm4_ctx, mechanism->cm_param,
		    SM4_BLOCK_LEN, sm4_encrypt_block, aes_copy_block,
		    aes_xor_block);
		break;
	default:
		rv = CRYPTO_MECHANISM_INVALID;
	}

	if (rv != CRYPTO_SUCCESS) {
		if (((aes_ctx_t *)sm4_ctx)->ac_flags &
		    PROVIDER_OWNS_KEY_SCHEDULE) {
			memset(keysched, 0, size);
			kmem_free(keysched, size);
		}
	}

	return (rv);
}

static int
sm4_encrypt_atomic(crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t template)
{
	aes_ctx_t sm4_ctx;
	off_t saved_offset;
	size_t saved_length;
	size_t length_needed;
	int ret;

	memset(&sm4_ctx, 0, sizeof (aes_ctx_t));

	ASSERT(ciphertext != NULL);

	if (mechanism->cm_type != SM4_GCM_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	ret = sm4_common_init_ctx(&sm4_ctx, template, mechanism, key,
	    KM_SLEEP, B_TRUE);
	if (ret != CRYPTO_SUCCESS)
		return (ret);

	length_needed = plaintext->cd_length + sm4_ctx.ac_tag_len;

	if (ciphertext->cd_length < length_needed) {
		ciphertext->cd_length = length_needed;
		ret = CRYPTO_BUFFER_TOO_SMALL;
		goto out;
	}

	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;

	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&sm4_ctx, plaintext, ciphertext,
		    sm4_encrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&sm4_ctx, plaintext, ciphertext,
		    sm4_encrypt_contiguous_blocks);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		ret = gcm_encrypt_final((gcm_ctx_t *)&sm4_ctx,
		    ciphertext, SM4_BLOCK_LEN, sm4_encrypt_block,
		    aes_copy_block, aes_xor_block);
		if (ret != CRYPTO_SUCCESS)
			goto out;
		ASSERT0(sm4_ctx.ac_remainder_len);

		if (plaintext != ciphertext) {
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
		}
	} else {
		ciphertext->cd_length = saved_length;
	}
	ciphertext->cd_offset = saved_offset;

out:
	if (sm4_ctx.ac_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		memset(sm4_ctx.ac_keysched, 0, sm4_ctx.ac_keysched_len);
		kmem_free(sm4_ctx.ac_keysched, sm4_ctx.ac_keysched_len);
	}
	if (sm4_ctx.ac_flags & GCM_MODE) {
		gcm_clear_ctx((gcm_ctx_t *)&sm4_ctx);
	}
	return (ret);
}

static int
sm4_decrypt_atomic(crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t template)
{
	aes_ctx_t sm4_ctx;
	off_t saved_offset;
	size_t saved_length;
	size_t length_needed;
	int ret;

	memset(&sm4_ctx, 0, sizeof (aes_ctx_t));

	ASSERT(plaintext != NULL);

	if (mechanism->cm_type != SM4_GCM_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	ret = sm4_common_init_ctx(&sm4_ctx, template, mechanism, key,
	    KM_SLEEP, B_FALSE);
	if (ret != CRYPTO_SUCCESS)
		return (ret);

	length_needed = ciphertext->cd_length - sm4_ctx.ac_tag_len;

	if (plaintext->cd_length < length_needed) {
		plaintext->cd_length = length_needed;
		ret = CRYPTO_BUFFER_TOO_SMALL;
		goto out;
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&sm4_ctx, ciphertext, plaintext,
		    sm4_decrypt_contiguous_blocks);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&sm4_ctx, ciphertext, plaintext,
		    sm4_decrypt_contiguous_blocks);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		ret = gcm_decrypt_final((gcm_ctx_t *)&sm4_ctx,
		    plaintext, SM4_BLOCK_LEN, sm4_encrypt_block,
		    aes_xor_block);
		ASSERT0(sm4_ctx.ac_remainder_len);
		if ((ret == CRYPTO_SUCCESS) &&
		    (ciphertext != plaintext)) {
			plaintext->cd_length =
			    plaintext->cd_offset - saved_offset;
		} else {
			plaintext->cd_length = saved_length;
		}
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;

out:
	if (sm4_ctx.ac_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		memset(sm4_ctx.ac_keysched, 0, sm4_ctx.ac_keysched_len);
		kmem_free(sm4_ctx.ac_keysched, sm4_ctx.ac_keysched_len);
	}
	if (sm4_ctx.ac_flags & GCM_MODE) {
		gcm_clear_ctx((gcm_ctx_t *)&sm4_ctx);
	}

	return (ret);
}
