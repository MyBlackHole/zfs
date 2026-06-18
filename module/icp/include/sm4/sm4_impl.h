// SPDX-License-Identifier: CDDL-1.0
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Common definitions used by SM4 (Chinese National Standard GB/T 32907-2016).
 * SM4 is a 128-bit block cipher with a 128-bit key, standardized as
 * ISO/IEC 18033-3:2010.
 */

#ifndef	_SM4_IMPL_H
#define	_SM4_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/zfs_context.h>
#include <sys/crypto/common.h>

#define	SM4_BLOCK_LEN	16	/* bytes (128-bit block) */
#define	SM4_KEY_LEN	16	/* bytes (128-bit key) */
#define	SM4_KEY_BITS	128	/* bits */
#define	SM4_ROUNDS	32	/* number of rounds */

/* SM4 key schedule structure */
typedef struct sm4_key {
	uint32_t rk[SM4_ROUNDS];	/* round keys */
} sm4_key_t;

/*
 * SM4 uses the same 128-bit block size as AES, so aes_copy_block and
 * aes_xor_block from the AES module are compatible and may be reused.
 *
 * Core SM4 functions.
 * ks is a pointer to sm4_key_t.
 */
extern void *sm4_alloc_keysched(size_t *size, int kmflag);
extern void sm4_init_keysched(const uint8_t *cipherKey, void *keysched);
extern int sm4_encrypt_block(const void *ks, const uint8_t *pt, uint8_t *ct);
extern int sm4_decrypt_block(const void *ks, const uint8_t *ct, uint8_t *pt);

/*
 * KCF provider registration (implemented in module/icp/io/sm4.c,
 * called from module/icp/illumos-crypto.c).
 */
extern int sm4_mod_init(void);
extern int sm4_mod_fini(void);

/*
 * SM4 mechanism types for use by the SM4 provider.
 */
typedef enum sm4_mech_type {
	SM4_GCM_MECH_INFO_TYPE,		/* SUN_CKM_SM4_GCM */
} sm4_mech_type_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SM4_IMPL_H */
