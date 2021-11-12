#ifndef	H_RPMPGP
#define	H_RPMPGP

/** \ingroup rpmpgp
 * \file rpmio/rpmpgp.h
 *
 * OpenPGP constants and structures from RFC-2440.
 *
 * Text from RFC-2440 in comments is
 *	Copyright (C) The Internet Society (1998).  All Rights Reserved.
 *
 * EdDSA algorithm identifier value taken from
 *      https://datatracker.ietf.org/doc/draft-ietf-openpgp-rfc4880bis/
 * This value is used in gnupg since version 2.1.0
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <rpm/rpmtypes.h>
#include <rpm/rpmstring.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmpgp
 */
typedef struct DIGEST_CTX_s * DIGEST_CTX;
typedef struct rpmDigestBundle_s * rpmDigestBundle;

/** \ingroup rpmpgp
 */
typedef struct pgpDig_s * pgpDig;

/** \ingroup rpmpgp
 */
typedef struct pgpDigParams_s * pgpDigParams;

/** \ingroup rpmpgp
 * 9.4. Hash Algorithms
 *
\verbatim
       ID           Algorithm                              Text Name
       --           ---------                              ---- ----
       1          - MD5                                    "MD5"
       2          - SHA-1                                  "SHA1"
       3          - RIPE-MD/160                            "RIPEMD160"
       4          - Reserved for double-width SHA (experimental)
       5          - MD2                                    "MD2"
       6          - Reserved for TIGER/192                 "TIGER192"
       7          - Reserved for HAVAL (5 pass, 160-bit)    "HAVAL-5-160"
       8          - SHA-256                                "SHA256"
       9          - SHA-384                                "SHA384"
       10         - SHA-512                                "SHA512"
       11         - SHA-224                                "SHA224"
       100 to 110 - Private/Experimental algorithm.
\endverbatim
 *
 * Implementations MUST implement SHA-1. Implementations SHOULD
 * implement MD5.
 */
typedef enum pgpHashAlgo_e {
    PGPHASHALGO_MD5		=  1,	/*!< MD5 */
    PGPHASHALGO_SHA1		=  2,	/*!< SHA1 */
    PGPHASHALGO_RIPEMD160	=  3,	/*!< RIPEMD160 */
    PGPHASHALGO_MD2		=  5,	/*!< MD2 */
    PGPHASHALGO_TIGER192	=  6,	/*!< TIGER192 */
    PGPHASHALGO_HAVAL_5_160	=  7,	/*!< HAVAL-5-160 */
    PGPHASHALGO_SHA256		=  8,	/*!< SHA256 */
    PGPHASHALGO_SHA384		=  9,	/*!< SHA384 */
    PGPHASHALGO_SHA512		= 10,	/*!< SHA512 */
    PGPHASHALGO_SHA224		= 11,	/*!< SHA224 */
} pgpHashAlgo;

/** \ingroup rpmpgp
 */
typedef enum pgpArmor_e {
    PGPARMOR_ERR_CRC_CHECK		= -7,
    PGPARMOR_ERR_BODY_DECODE		= -6,
    PGPARMOR_ERR_CRC_DECODE		= -5,
    PGPARMOR_ERR_NO_END_PGP		= -4,
    PGPARMOR_ERR_UNKNOWN_PREAMBLE_TAG	= -3,
    PGPARMOR_ERR_UNKNOWN_ARMOR_TYPE	= -2,
    PGPARMOR_ERR_NO_BEGIN_PGP		= -1,
#define	PGPARMOR_ERROR	PGPARMOR_ERR_NO_BEGIN_PGP
    PGPARMOR_NONE		=  0,
    PGPARMOR_MESSAGE		=  1, /*!< MESSAGE */
    PGPARMOR_PUBKEY		=  2, /*!< PUBLIC KEY BLOCK */
    PGPARMOR_SIGNATURE		=  3, /*!< SIGNATURE */
    PGPARMOR_SIGNED_MESSAGE	=  4, /*!< SIGNED MESSAGE */
    PGPARMOR_FILE		=  5, /*!< ARMORED FILE */
    PGPARMOR_PRIVKEY		=  6, /*!< PRIVATE KEY BLOCK */
    PGPARMOR_SECKEY		=  7  /*!< SECRET KEY BLOCK */
} pgpArmor;

/** \ingroup rpmpgp
 * Bit(s) to control digest operation.
 */
enum rpmDigestFlags_e {
    RPMDIGEST_NONE	= 0
};

typedef rpmFlags rpmDigestFlags;

/** \ingroup rpmpgp
 * Parse armored OpenPGP packets from memory.
 * @param armor		armored OpenPGP packet string
 * @param[out] pkt	dearmored OpenPGP packet(s) (malloced)
 * @param[out] pktlen	dearmored OpenPGP packet(s) length in bytes
 * @return		type of armor found
 */
pgpArmor pgpParsePkts(const char *armor, uint8_t ** pkt, size_t * pktlen);

/** \ingroup rpmpgp
 * Perform cryptography initialization.
 * It must be called before any cryptography can be used within rpm.
 * It's not normally necessary to call it directly as it's called in
 * general rpm initialization routines.
 * @return		0 on success, -1 on failure
 */
int rpmInitCrypto(void);

/** \ingroup rpmpgp
 * Shutdown cryptography
 */
int rpmFreeCrypto(void);

/** \ingroup rpmpgp
 * Duplicate a digest context.
 * @param octx		existing digest context
 * @return		duplicated digest context
 */
DIGEST_CTX rpmDigestDup(DIGEST_CTX octx);

/** \ingroup rpmpgp
 * Obtain digest length in bytes.
 * @param hashalgo	type of digest
 * @return		digest length, zero on invalid algorithm
 */
size_t rpmDigestLength(int hashalgo);

/** \ingroup rpmpgp
 * Initialize digest.
 * Set bit count to 0 and buffer to mysterious initialization constants.
 * @param hashalgo	type of digest
 * @param flags		bit(s) to control digest operation
 * @return		digest context
 */
DIGEST_CTX rpmDigestInit(int hashalgo, rpmDigestFlags flags);

/** \ingroup rpmpgp
 * Update context with next plain text buffer.
 * @param ctx		digest context
 * @param data		next data buffer
 * @param len		no. bytes of data
 * @return		0 on success
 */
int rpmDigestUpdate(DIGEST_CTX ctx, const void * data, size_t len);

/** \ingroup rpmpgp
 * Return digest and destroy context.
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 *
 * @param ctx		digest context
 * @param[out] datap	address of returned digest
 * @param[out] lenp	address of digest length
 * @param asAscii	return digest as ascii string?
 * @return		0 on success
 */
int rpmDigestFinal(DIGEST_CTX ctx,
	void ** datap,
	size_t * lenp, int asAscii);

/** \ingroup rpmpgp
 * Create a new digest bundle.
 * @return		New digest bundle
 */
rpmDigestBundle rpmDigestBundleNew(void);

/** \ingroup rpmpgp
 * Free a digest bundle and all contained digest contexts.
 * @param bundle	digest bundle
 * @return		NULL always
 */
rpmDigestBundle rpmDigestBundleFree(rpmDigestBundle bundle);

/** \ingroup rpmpgp
 * Add a new type of digest to a bundle. Same as calling
 * rpmDigestBundleAddID() with algo == id value.
 * @param bundle	digest bundle
 * @param algo		type of digest
 * @param flags		bit(s) to control digest operation
 * @return		0 on success
 */
int rpmDigestBundleAdd(rpmDigestBundle bundle, int algo,
			rpmDigestFlags flags);

/** \ingroup rpmpgp
 * Add a new type of digest to a bundle.
 * @param bundle	digest bundle
 * @param algo		type of digest
 * @param id		id of digest (arbitrary, must be > 0)
 * @param flags		bit(s) to control digest operation
 * @return		0 on success
 */
int rpmDigestBundleAddID(rpmDigestBundle bundle, int algo, int id,
			 rpmDigestFlags flags);

/** \ingroup rpmpgp
 * Update contexts within bundle with next plain text buffer.
 * @param bundle	digest bundle
 * @param data		next data buffer
 * @param len		no. bytes of data
 * @return		0 on success
 */
int rpmDigestBundleUpdate(rpmDigestBundle bundle, const void *data, size_t len);

/** \ingroup rpmpgp
 * Return digest from a bundle and destroy context, see rpmDigestFinal().
 *
 * @param bundle	digest bundle
 * @param id		id of digest to return
 * @param[out] datap	address of returned digest
 * @param[out] lenp	address of digest length
 * @param asAscii	return digest as ascii string?
 * @return		0 on success
 */
int rpmDigestBundleFinal(rpmDigestBundle bundle, int id,
			 void ** datap, size_t * lenp, int asAscii);

/** \ingroup rpmpgp
 * Duplicate a digest context from a bundle.
 * @param bundle	digest bundle
 * @param id		id of digest to dup
 * @return		duplicated digest context
 */
DIGEST_CTX rpmDigestBundleDupCtx(rpmDigestBundle bundle, int id);

#ifdef __cplusplus
}
#endif

#endif	/* H_RPMPGP */
