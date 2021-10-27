#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>


#include "system.h"
#include <errno.h>
#include <sys/wait.h>
#include <termios.h>

#include <popt.h>
#include <rpm/rpmcli.h>
#include <rpm/rpmsign.h>
#include "cliutils.h"
#include "debug.h"

#include <rpmio/rpmkeyring.h>
#include <rpmio/rpmpgp.h>
#include <rpmio/digest.h>
#include <rpmio/rpmio_internal.h>

enum modes {
    MODE_NONE    = 0,
    MODE_SIGN = (1 << 0),
    MODE_VERIFY  = (1 << 1),
};

static int mode = MODE_NONE;

static struct poptOption signOptsTable[] = {
    { "sign", '\0', (POPT_ARG_VAL|POPT_ARGFLAG_OR), &mode, MODE_SIGN,
	"sign", NULL },
    { "verify", '\0', (POPT_ARG_VAL|POPT_ARGFLAG_OR), &mode, MODE_VERIFY,
	"verify", NULL },
    POPT_TABLEEND
};

static struct poptOption optionsTable[] = {
    { NULL, '\0', POPT_ARG_INCLUDE_TABLE, signOptsTable, 0,
	N_("Signature options:"), NULL },
    { NULL, '\0', POPT_ARG_INCLUDE_TABLE, rpmcliAllPoptTable, 0,
	N_("Common options for all rpm modes and executables:"), NULL },

    POPT_AUTOALIAS
    POPT_AUTOHELP
    POPT_TABLEEND
};

int main(int argc, char *argv[])
{
    int ec = EXIT_FAILURE;
    int rc;
    poptContext optCon = NULL;
    int verbose = 0;

    xsetprogname(argv[0]); /* Portability call -- see system.h */

    optCon = rpmcliInit(argc, argv, optionsTable);

    if (argc <= 1) {
	printUsage(optCon, stderr, 0);
	goto exit;
    }

    const char *command = poptGetArg(optCon);
    if (command == NULL) {
	fprintf(stderr, "No command given\n");
    } else if (strcmp(command, "version") == 0) {
	printf("rpmsop 4.17.90\n");
	ec = EXIT_SUCCESS;
    } else if (strcmp(command, "verify") == 0) {
	/* Read in the armored signature.  Assume it is armored for now.  */
	uint8_t *pkt;
	size_t pktlen;
	const char *filename = poptGetArg(optCon);
	if (filename == NULL) {
	    fprintf(stderr, "Missing signature argument\n");
	    goto exit;
	}
	pgpArmor armor = pgpReadPkts(filename, &pkt, &pktlen);
	if (armor <= PGPARMOR_ERROR) {
	    fprintf(stderr, "Failed to read signature %s: %d\n",
		    filename, armor);
	    goto exit;
	}
	if (armor != PGPARMOR_SIGNATURE) {
	    fprintf(stderr, "Not a signature: %d\n", armor);
	    goto exit;
	}

	pgpDigParams sig;
	if ((rc = pgpPrtParams(pkt, pktlen, 0, &sig))) {
	    ec = rc;
	    fprintf(stderr, "Failed to parse signature: %d\n", ec);
	    goto exit;
	}
	free(pkt);

	rpmKeyring certring = rpmKeyringNew();
	while ((filename = poptGetArg(optCon)) != NULL) {
	    rpmPubkey cert = rpmPubkeyRead(filename);
	    if (cert == NULL) {
		/* Maybe it wasn't armored.  */
		uint8_t *b = NULL;
		ssize_t blen;
		if ((rc = rpmioSlurp(filename, &b, &blen))) {
		    ec = rc;
		    fprintf(stderr, "Failed to read cert: %s\n", filename);
		    goto exit;
		}
		cert = rpmPubkeyNew(b, blen);
		if (cert == NULL) {
		    fprintf(stderr, "Failed to parse cert: %s\n", filename);
		    goto exit;
		}
	    }

	    rpmKeyringAddKey(certring, cert);

	    /* Now add the subkeys.  */
	    int count;
	    rpmPubkey *subkeys = rpmGetSubkeys(cert, &count);
	    if (verbose)
		fprintf(stderr, "Cert has %d signing-capable subkeys...\n",
			count);
	    for (int i = 0; i < count; i++) {
		if (verbose)
		    fprintf(stderr, "Adding subkey %d...\n", i);
		rpmKeyringAddKey(certring, subkeys[i]);
		rpmPubkeyFree(subkeys[i]);
	    }
	    free(subkeys);
	    rpmPubkeyFree(cert);
	}

	/* Now hash the data.  */
	char buffer[4096];
	ssize_t bytes_read;
	DIGEST_CTX ctx = rpmDigestInit(sig->hash_algo, 0);

	while ((bytes_read = read(0, buffer, sizeof(buffer))) > 0) {
	    rpmDigestUpdate(ctx, buffer, bytes_read);
	}
	if (bytes_read < 0) {
	    fprintf(stderr, "Failed to read data\n");
	    goto exit;
	}

	ec = rpmKeyringVerifySig(certring, sig, ctx);
	rpmDigestFinal(ctx, NULL, NULL, 0);
	pgpDigParamsFree(sig);
	rpmKeyringFree(certring);

	if (ec == RPMRC_NOKEY) {
	    fprintf(stderr, "Signing key not found.\n");
	}
    } else {
	fprintf(stderr, "Unknown command: %s\n", command);
	return 69; /* UNSUPPORTED_SUBCOMMAND */
    }

exit:
    rpmcliFini(optCon);
    return RETVAL(ec);
}
