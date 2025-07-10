#include "system.h"

#include <gcrypt.h>

#include <rpm/rpmcrypto.h>
#include "rpmpgp_internal.h"
#include "rpmio_internal.h"
#include <rpm/rpmlog.h>
#include "debug.h"

static int is_gost_curve(const char *oid)
{
    return oid && strcmp(oid, "1.2.643.2.2.35.1") == 0;
}

/**
 * MD5/SHA1 digest private data.
 */
struct DIGEST_CTX_s {
    rpmDigestFlags flags;	/*!< Bit(s) to control digest operation. */
    int algo;			/*!< Used hash algorithm */
    gcry_md_hd_t h;
};


/****************************  init   ************************************/

int rpmInitCrypto(void) {
    gcry_check_version (NULL);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    return 0;
}

int rpmFreeCrypto(void) {
    return 0;
}

/****************************  digest ************************************/

size_t rpmDigestLength(int hashalgo)
{
    switch (hashalgo) {
    case RPM_HASH_MD5:
	return 16;
    case RPM_HASH_SHA1:
	return 20;
    case RPM_HASH_SHA224:
        return 28;
    case RPM_HASH_GOST12_256:
        return 32;
    case RPM_HASH_SHA256:
	return 32;
    case RPM_HASH_SHA384:
	return 48;
    case RPM_HASH_SHA512:
        return 64;
    case RPM_HASH_GOSTR3411_2012_256:
        return 32;
    case RPM_HASH_GOSTR3411_2012_512:
        return 64;
    case RPM_HASH_GOSTR3411_94:
        return 32;
    default:
	return 0;
    }
}

static int hashalgo2gcryalgo(int hashalgo)
{
    switch (hashalgo) {
    case RPM_HASH_MD5:
	return GCRY_MD_MD5;
    case RPM_HASH_SHA1:
	return GCRY_MD_SHA1;
    case RPM_HASH_SHA224:
	return GCRY_MD_SHA224;
    case RPM_HASH_SHA256:
	return GCRY_MD_SHA256;
    case RPM_HASH_SHA384:
	return GCRY_MD_SHA384;
    case RPM_HASH_SHA512:
        return GCRY_MD_SHA512;
    case RPM_HASH_GOST12_256:
#ifdef GCRY_MD_GOSTR3411_12_256
        return GCRY_MD_GOSTR3411_12_256;
#else
        return GCRY_MD_STRIBOG256;
#endif
    case RPM_HASH_GOSTR3411_2012_256:
        return GCRY_MD_STRIBOG256;
    case RPM_HASH_GOSTR3411_2012_512:
        return GCRY_MD_STRIBOG512;
    case RPM_HASH_GOSTR3411_94:
        return GCRY_MD_GOSTR3411_CP;
    default:
	return 0;
    }
}

DIGEST_CTX rpmDigestInit(int hashalgo, rpmDigestFlags flags)
{
    gcry_md_hd_t h;
    DIGEST_CTX ctx;
    int gcryalgo = hashalgo2gcryalgo(hashalgo);

    if (!gcryalgo || gcry_md_open(&h, gcryalgo, 0) != 0)
	return NULL;

    ctx = xcalloc(1, sizeof(*ctx));
    ctx->flags = flags;
    ctx->algo = hashalgo;
    ctx->h = h;
    return ctx;
}

int rpmDigestUpdate(DIGEST_CTX ctx, const void * data, size_t len)
{
    if (ctx == NULL)
	return -1;
    gcry_md_write(ctx->h, data, len);
    return 0;
}

int rpmDigestFinal(DIGEST_CTX ctx, void ** datap, size_t *lenp, int asAscii)
{
    unsigned char *digest;
    int digestlen;
    if (ctx == NULL)
	return -1;
    digest = gcry_md_read(ctx->h, 0);
    digestlen = rpmDigestLength(ctx->algo);
    if (!asAscii) {
	if (lenp)
	    *lenp = digestlen;
	if (datap) {
	    *datap = xmalloc(digestlen);
	    memcpy(*datap, digest, digestlen);
	}
    } else {
	if (lenp)
	    *lenp = 2 * digestlen + 1;
	if (datap) {
	    *datap = rpmhex((const uint8_t *)digest, digestlen);
	}
    }
    gcry_md_close(ctx->h);
    free(ctx);
    return 0;
}

DIGEST_CTX rpmDigestDup(DIGEST_CTX octx)
{
    DIGEST_CTX nctx = NULL;
    if (octx) {
        gcry_md_hd_t h;
	if (gcry_md_copy(&h, octx->h))
	    return NULL;
	nctx = memcpy(xcalloc(1, sizeof(*nctx)), octx, sizeof(*nctx));
	nctx->h = h;
    }
    return nctx;
}


/****************************** RSA **************************************/

struct pgpDigSigRSA_s {
    gcry_mpi_t s;
};

struct pgpDigKeyRSA_s {
    gcry_mpi_t n;
    gcry_mpi_t e;
};

static int pgpSetSigMpiRSA(pgpDigAlg pgpsig, int num, const uint8_t *p)
{
    struct pgpDigSigRSA_s *sig = pgpsig->data;
    int mlen = pgpMpiLen(p);
    int rc = 1;

    if (!sig)
	sig = pgpsig->data = xcalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    }
    return rc;
}

static int pgpSetKeyMpiRSA(pgpDigAlg pgpkey, int num, const uint8_t *p)
{
    struct pgpDigKeyRSA_s *key = pgpkey->data;
    int mlen = pgpMpiLen(p);
    int rc = 1;

    if (!key)
	key = pgpkey->data = xcalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&key->n, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    case 1:
	if (!gcry_mpi_scan(&key->e, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    }
    return rc;
}

static int pgpVerifySigRSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig, uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgpDigKeyRSA_s *key = pgpkey->data;
    struct pgpDigSigRSA_s *sig = pgpsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    const char *hash_algo_name;
    int rc = 1;

    if (!sig || !key)
	return rc;

    hash_algo_name = gcry_md_algo_name(hashalgo2gcryalgo(hash_algo));
    gcry_sexp_build(&sexp_sig, NULL, "(sig-val (rsa (s %M)))", sig->s);
    gcry_sexp_build(&sexp_data, NULL, "(data (flags pkcs1) (hash %s %b))", hash_algo_name, (int)hashlen, (const char *)hash);
    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (rsa (n %M) (e %M)))", key->n, key->e);
    if (sexp_sig && sexp_data && sexp_pkey)
	rc = gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0 ? 0 : 1;
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}

static void pgpFreeSigRSA(pgpDigAlg pgpsig)
{
    struct pgpDigSigRSA_s *sig = pgpsig->data;
    if (sig) {
        gcry_mpi_release(sig->s);
	pgpsig->data = _free(sig);
    }
}

static void pgpFreeKeyRSA(pgpDigAlg pgpkey)
{
    struct pgpDigKeyRSA_s *key = pgpkey->data;
    if (key) {
        gcry_mpi_release(key->n);
        gcry_mpi_release(key->e);
	pgpkey->data = _free(key);
    }
}


/****************************** DSA **************************************/

struct pgpDigSigDSA_s {
    gcry_mpi_t r;
    gcry_mpi_t s;
};

struct pgpDigKeyDSA_s {
    gcry_mpi_t p;
    gcry_mpi_t q;
    gcry_mpi_t g;
    gcry_mpi_t y;
};

static int pgpSetSigMpiDSA(pgpDigAlg pgpsig, int num, const uint8_t *p)
{
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    int mlen = pgpMpiLen(p);
    int rc = 1;

    if (!sig)
	sig = pgpsig->data = xcalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&sig->r, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    case 1:
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    }
    return rc;
}

static int pgpSetKeyMpiDSA(pgpDigAlg pgpkey, int num, const uint8_t *p)
{
    struct pgpDigKeyDSA_s *key = pgpkey->data;
    int mlen = pgpMpiLen(p);
    int rc = 1;

    if (!key)
	key = pgpkey->data = xcalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&key->p, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    case 1:
	if (!gcry_mpi_scan(&key->q, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    case 2:
	if (!gcry_mpi_scan(&key->g, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    case 3:
	if (!gcry_mpi_scan(&key->y, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    }
    return rc;
}

static int pgpVerifySigDSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig, uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgpDigKeyDSA_s *key = pgpkey->data;
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    int rc = 1;
    size_t qlen;

    if (!sig || !key)
	return rc;

    qlen = (mpi_get_nbits(key->q) + 7) / 8;
    if (qlen < 20)
	qlen = 20;		/* sanity */
    if (hashlen > qlen)
	hashlen = qlen;		/* dsa2: truncate hash to qlen */
    gcry_sexp_build(&sexp_sig, NULL, "(sig-val (dsa (r %M) (s %M)))", sig->r, sig->s);
    gcry_sexp_build(&sexp_data, NULL, "(data (flags raw) (value %b))", (int)hashlen, (const char *)hash);
    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (dsa (p %M) (q %M) (g %M) (y %M)))", key->p, key->q, key->g, key->y);
    if (sexp_sig && sexp_data && sexp_pkey)
	rc = gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0 ? 0 : 1;
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}

static void pgpFreeSigDSA(pgpDigAlg pgpsig)
{
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    if (sig) {
        gcry_mpi_release(sig->r);
        gcry_mpi_release(sig->s);
	pgpsig->data = _free(sig);
    }
}

static void pgpFreeKeyDSA(pgpDigAlg pgpkey)
{
    struct pgpDigKeyDSA_s *key = pgpkey->data;
    if (key) {
        gcry_mpi_release(key->p);
        gcry_mpi_release(key->q);
        gcry_mpi_release(key->g);
        gcry_mpi_release(key->y);
	pgpkey->data = _free(key);
    }
}

static int pgpVerifySigGOST2001(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                                uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgpDigKeyDSA_s *key = pgpkey->data;
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    int rc = 1;

    if (!sig || !key)
        return rc;

    gcry_sexp_build(&sexp_sig, NULL,
                    "(sig-val (gost (r %M) (s %M)))", sig->r, sig->s);
    gcry_sexp_build(&sexp_data, NULL,
                    "(data (flags raw) (value %b))", (int)hashlen, (const char *)hash);
    gcry_sexp_build(&sexp_pkey, NULL,
                    "(public-key (gost (p %M) (q %M) (y %M)))",
                    key->p, key->q, key->y);
    if (sexp_sig && sexp_data && sexp_pkey) {
        char buf[1024];
        gcry_sexp_sprint(sexp_sig, GCRYSEXP_FMT_CANON, buf, sizeof(buf));
        rpmlog(RPMLOG_DEBUG, "pgpVerifySigGOST2001: sig %s\n", buf);
        gcry_sexp_sprint(sexp_data, GCRYSEXP_FMT_CANON, buf, sizeof(buf));
        rpmlog(RPMLOG_DEBUG, "pgpVerifySigGOST2001: data %s\n", buf);
        gcry_sexp_sprint(sexp_pkey, GCRYSEXP_FMT_CANON, buf, sizeof(buf));
        rpmlog(RPMLOG_DEBUG, "pgpVerifySigGOST2001: pkey %s\n", buf);
    }
    if (sexp_sig && sexp_data && sexp_pkey)
        rc = (gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0) ? 0 : 1;
	
    rpmlog(RPMLOG_DEBUG, "pgpVerifySigGOST2001: rc=%d\n", rc);

    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}

struct pgpDigSigEDDSA_s {
    gcry_mpi_t r;
    gcry_mpi_t s;
};

struct pgpDigKeyEDDSA_s {
    gcry_mpi_t q;
};

static int pgpVerifySigGOST2012(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                                uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgpDigKeyEDDSA_s *key = pgpkey->data;
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    int rc = 1;

    if (!sig || !key)
        return rc;

    gcry_sexp_build(&sexp_sig, NULL,
                    "(sig-val (ecc (r %M) (s %M)))", sig->r, sig->s);
    gcry_sexp_build(&sexp_data, NULL,
                    "(data (flags raw) (value %b))", (int)hashlen, (const char *)hash);
    gcry_sexp_build(&sexp_pkey, NULL,
                    "(public-key (ecc (curve \"GOST2012-256-A\") (q %M)))",
                    key->q);
    if (sexp_sig && sexp_data && sexp_pkey)
        rc = gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0 ? 0 : 1;
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}

static const char *pgpCurveName(int curve)
{
    switch (curve) {
    case PGPCURVE_NIST_P_256:
        return "NIST P-256";
    case PGPCURVE_NIST_P_384:
        return "NIST P-384";
    case PGPCURVE_NIST_P_521:
        return "NIST P-521";
    case PGPCURVE_BRAINPOOL_P256R1:
        return "brainpoolP256r1";
    case PGPCURVE_BRAINPOOL_P512R1:
        return "brainpoolP512r1";
    case PGPCURVE_ED25519:
        return "Ed25519";
    case PGPCURVE_CURVE25519:
        return "Curve25519";
    default:
        return NULL;
    }
}

static int pgpVerifySigECDSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                             uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgpDigKeyEDDSA_s *key = pgpkey->data;
    struct pgpDigSigDSA_s *sig = pgpsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    const char *curve_name = pgpCurveName(pgpkey->curve);
    const char *hash_algo_name;
    int rc = 1;

    if (!sig || !key || !curve_name)
        return rc;

    hash_algo_name = gcry_md_algo_name(hashalgo2gcryalgo(hash_algo));
    gcry_sexp_build(&sexp_sig, NULL,
                    "(sig-val (ecdsa (r %M) (s %M)))", sig->r, sig->s);
    gcry_sexp_build(&sexp_data, NULL,
                    "(data (flags raw) (hash %s %b))", hash_algo_name,
                    (int)hashlen, (const char *)hash);
    gcry_sexp_build(&sexp_pkey, NULL,
                    "(public-key (ecc (curve \"%s\") (q %M)))",
                    curve_name, key->q);
    if (sexp_sig && sexp_data && sexp_pkey) {
        char buf[1024];
        gcry_sexp_sprint(sexp_sig, GCRYSEXP_FMT_CANON, buf, sizeof(buf));
        rpmlog(RPMLOG_DEBUG, "pgpVerifySigECDSA: sig %s\n", buf);
        gcry_sexp_sprint(sexp_data, GCRYSEXP_FMT_CANON, buf, sizeof(buf));
        rpmlog(RPMLOG_DEBUG, "pgpVerifySigECDSA: data %s\n", buf);
        gcry_sexp_sprint(sexp_pkey, GCRYSEXP_FMT_CANON, buf, sizeof(buf));
        rpmlog(RPMLOG_DEBUG, "pgpVerifySigECDSA: pkey %s\n", buf);
        rc = gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0 ? 0 : 1;
    }
    rpmlog(RPMLOG_DEBUG, "pgpVerifySigECDSA: rc=%d\n", rc);
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}



/****************************** EDDSA **************************************/

static int pgpSetSigMpiEDDSA(pgpDigAlg pgpsig, int num, const uint8_t *p)
{
    struct pgpDigSigEDDSA_s *sig = pgpsig->data;
    int mlen = pgpMpiLen(p);
    int rc = 1;

    if (!sig)
	sig = pgpsig->data = xcalloc(1, sizeof(*sig));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&sig->r, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    case 1:
	if (!gcry_mpi_scan(&sig->s, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    }
    return rc;
}

static int pgpSetKeyMpiEDDSA(pgpDigAlg pgpkey, int num, const uint8_t *p)
{
    struct pgpDigKeyEDDSA_s *key = pgpkey->data;
    int mlen = pgpMpiLen(p);
    int rc = 1;

    if (!key)
	key = pgpkey->data = xcalloc(1, sizeof(*key));

    switch (num) {
    case 0:
	if (!gcry_mpi_scan(&key->q, GCRYMPI_FMT_PGP, p, mlen, NULL))
	    rc = 0;
	break;
    }
    return rc;
}

static int
ed25519_zero_extend(gcry_mpi_t x, unsigned char *buf, int bufl)
{
    int n = (gcry_mpi_get_nbits(x) + 7) / 8;
    if (n == 0 || n > bufl)
	return 1;
    n = bufl - n;
    if (n)
	memset(buf, 0, n);
    gcry_mpi_print(GCRYMPI_FMT_USG, buf + n, bufl - n, NULL, x);
    return 0;
}

static int pgpVerifySigEDDSA(pgpDigAlg pgpkey, pgpDigAlg pgpsig, uint8_t *hash, size_t hashlen, int hash_algo)
{
    struct pgpDigKeyEDDSA_s *key = pgpkey->data;
    struct pgpDigSigEDDSA_s *sig = pgpsig->data;
    gcry_sexp_t sexp_sig = NULL, sexp_data = NULL, sexp_pkey = NULL;
    int rc = 1;
    unsigned char buf_r[32], buf_s[32];

    if (!sig || !key)
	return rc;
    if (pgpkey->curve != PGPCURVE_ED25519)
	return rc;
    if (ed25519_zero_extend(sig->r, buf_r, 32) || ed25519_zero_extend(sig->s, buf_s, 32))
	return rc;
    gcry_sexp_build(&sexp_sig, NULL, "(sig-val (eddsa (r %b) (s %b)))", 32, (const char *)buf_r, 32, (const char *)buf_s, 32);
    gcry_sexp_build(&sexp_data, NULL, "(data (flags eddsa) (hash-algo sha512) (value %b))", (int)hashlen, (const char *)hash);
    gcry_sexp_build(&sexp_pkey, NULL, "(public-key (ecc (curve \"Ed25519\") (flags eddsa) (q %M)))", key->q);
    if (sexp_sig && sexp_data && sexp_pkey)
	rc = gcry_pk_verify(sexp_sig, sexp_data, sexp_pkey) == 0 ? 0 : 1;
    gcry_sexp_release(sexp_sig);
    gcry_sexp_release(sexp_data);
    gcry_sexp_release(sexp_pkey);
    return rc;
}

static void pgpFreeSigEDDSA(pgpDigAlg pgpsig)
{
    struct pgpDigSigEDDSA_s *sig = pgpsig->data;
    if (sig) {
	gcry_mpi_release(sig->r);
	gcry_mpi_release(sig->s);
	pgpsig->data = _free(sig);
    }
}

static void pgpFreeKeyEDDSA(pgpDigAlg pgpkey)
{
    struct pgpDigKeyEDDSA_s *key = pgpkey->data;
    if (key) {
	gcry_mpi_release(key->q);
	pgpkey->data = _free(key);
    }
}


/****************************** NULL **************************************/

static int pgpSetMpiNULL(pgpDigAlg pgpkey, int num, const uint8_t *p)
{
    return 1;
}

static int pgpVerifyNULL(pgpDigAlg pgpkey, pgpDigAlg pgpsig,
                         uint8_t *hash, size_t hashlen, int hash_algo)
{
    return 1;
}

static int pgpSupportedCurve(int curve)
{
    if (curve == PGPCURVE_ED25519) {
	static int supported_ed25519;
	if (!supported_ed25519) {
	    gcry_sexp_t sexp = NULL;
	    unsigned int nbits;
	    gcry_sexp_build(&sexp, NULL, "(public-key (ecc (curve \"Ed25519\")))");
	    nbits = gcry_pk_get_nbits(sexp);
	    gcry_sexp_release(sexp);
	    supported_ed25519 = nbits > 0 ? 1 : -1;
	}
	return supported_ed25519 > 0;
    }
    return 0;
}

pgpDigAlg pgpPubkeyNew(int algo, int curve, const char *oid)
{
    pgpDigAlg ka = xcalloc(1, sizeof(*ka));;
    ka->curve = curve;
    ka->is_gost = is_gost_curve(oid);
    if (ka->is_gost && algo == PGPPUBKEYALGO_ECDSA)
        algo = PGPPUBKEYALGO_GOST3410_2001;

    switch (algo) {
    case PGPPUBKEYALGO_RSA:
        ka->setmpi = pgpSetKeyMpiRSA;
        ka->free = pgpFreeKeyRSA;
        ka->mpis = 2;
        break;
    case PGPPUBKEYALGO_DSA:
    case PGPPUBKEYALGO_GOST3410_2001_A:
    case PGPPUBKEYALGO_GOST3410_2001_B:
    case PGPPUBKEYALGO_GOST3410_2001_C:
    case PGPPUBKEYALGO_GOST3410_2001_XCHA:
        ka->setmpi = pgpSetKeyMpiDSA;
        ka->free = pgpFreeKeyDSA;
        ka->mpis = 4;
        break;
    case PGPPUBKEYALGO_ECDSA:
        /* Treat GOST ECDSA keys like regular ECDSA */
        ka->setmpi = pgpSetKeyMpiEDDSA;
        ka->free   = pgpFreeKeyEDDSA;
        ka->mpis   = 1;
        ka->curve = curve;
        break;
#if PGPPUBKEYALGO_GOST3410_2001 != PGPPUBKEYALGO_ECDSA
    case PGPPUBKEYALGO_GOST3410_2001:
        /* GOST R 34.10-2001 обрабатывается через DSA-механизм (4 MPI: p, q, g, y) */
        ka->setmpi = pgpSetKeyMpiDSA;
        ka->free   = pgpFreeKeyDSA;
        ka->mpis   = 4;
        break;
#endif
    case PGPPUBKEYALGO_GOST3410_2012_256:
        ka->setmpi = pgpSetKeyMpiEDDSA;
        ka->free = pgpFreeKeyEDDSA;
        ka->mpis = 1;
        break;
    case PGPPUBKEYALGO_EDDSA:
	if (!pgpSupportedCurve(curve)) {
	    ka->setmpi = pgpSetMpiNULL;
	    ka->mpis = -1;
	    break;
	}
        ka->setmpi = pgpSetKeyMpiEDDSA;
        ka->free = pgpFreeKeyEDDSA;
        ka->mpis = 1;
        ka->curve = curve;
        break;
    default:
        ka->setmpi = pgpSetMpiNULL;
        ka->mpis = -1;
        break;
    }

    ka->verify = pgpVerifyNULL; /* keys can't be verified */
    rpmlog(RPMLOG_DEBUG,
           "pgpPubkeyNew: algo=%d curve_oid=%s is_gost=%d mpis=%d setmpi=%p free=%p\n",
           algo, oid ? oid : "", ka->is_gost,
           ka->mpis, ka->setmpi, ka->free);
    return ka;
}

pgpDigAlg pgpSignatureNew(int algo, int is_gost)
{
    pgpDigAlg sa = xcalloc(1, sizeof(*sa));
    sa->is_gost = is_gost;


    switch (algo) {
    case PGPPUBKEYALGO_RSA:
        sa->setmpi = pgpSetSigMpiRSA;
        sa->free = pgpFreeSigRSA;
        sa->verify = pgpVerifySigRSA;
        sa->mpis = 1;
        break;
    case PGPPUBKEYALGO_DSA:
    case PGPPUBKEYALGO_GOST3410_2001_A:
    case PGPPUBKEYALGO_GOST3410_2001_B:
    case PGPPUBKEYALGO_GOST3410_2001_C:
    case PGPPUBKEYALGO_GOST3410_2001_XCHA:
        sa->setmpi = pgpSetSigMpiDSA;
        sa->free = pgpFreeSigDSA;
        sa->verify = pgpVerifySigDSA;
        sa->mpis = 2;
        break;
#if PGPPUBKEYALGO_GOST3410_2001 != PGPPUBKEYALGO_ECDSA
    case PGPPUBKEYALGO_GOST3410_2001:
        sa->setmpi = pgpSetSigMpiDSA;
        sa->free = pgpFreeSigDSA;
        sa->verify = pgpVerifySigGOST2001;
        sa->mpis = 2;
        break;
#endif
    case PGPPUBKEYALGO_ECDSA:
        sa->setmpi = pgpSetSigMpiDSA;
        sa->free = pgpFreeSigDSA;
        sa->verify = is_gost ? pgpVerifySigGOST2001 : pgpVerifySigECDSA;
        sa->mpis = 2;
        break;
    case PGPPUBKEYALGO_GOST3410_2012_256:
        sa->setmpi = pgpSetSigMpiDSA;
        sa->free = pgpFreeSigDSA;
        sa->verify = pgpVerifySigGOST2012;
        sa->mpis = 2;
        break;
    case PGPPUBKEYALGO_EDDSA:
        sa->setmpi = pgpSetSigMpiEDDSA;
        sa->free = pgpFreeSigEDDSA;
        sa->verify = pgpVerifySigEDDSA;
        sa->mpis = 2;
        break;
    default:
        sa->setmpi = pgpSetMpiNULL;
        sa->verify = pgpVerifyNULL;
        sa->mpis = -1;
        break;
    }
    rpmlog(RPMLOG_DEBUG, "pgpSignatureNew: algo=%d is_gost=%d verify=%p\n",
           algo, is_gost, sa->verify);
    return sa;
}
