#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "md5.h"
#include "messages.h"
#include "rpmlib.h"

static char * SCRIPT_PATH = "PATH=/sbin:/bin:/usr/sbin:/usr/bin:"
			                 "/usr/X11R6/bin\nexport PATH\n";

int rpmVerifyFile(char * prefix, Header h, int filenum, int * result) {
    char ** fileList, ** md5List, ** linktoList;
    int_32 * verifyFlags, flags;
    int_32 * sizeList, * mtimeList;
    unsigned short * modeList, * rdevList;
    char * fileStatesList;
    char * filespec;
    int type, count, rc;
    struct stat sb;
    unsigned char md5sum[40];
    char linkto[1024];
    int size;
    int_32 * uidList, * gidList;
    int useBrokenMd5;

    if (headerGetEntry(h, RPMTAG_RPMVERSION, NULL, NULL, NULL))
	useBrokenMd5 = 0;
    else
	useBrokenMd5 = 1;

    headerGetEntry(h, RPMTAG_FILEMODES, &type, (void **) &modeList, &count);

    if (headerGetEntry(h, RPMTAG_FILEVERIFYFLAGS, &type, (void **) &verifyFlags, 
		 &count)) {
	flags = verifyFlags[filenum];
    } else {
	flags = RPMVERIFY_ALL;
    }

    headerGetEntry(h, RPMTAG_FILENAMES, &type, (void **) &fileList, &count);
    filespec = alloca(strlen(fileList[filenum]) + strlen(prefix) + 5);
    strcpy(filespec, prefix);
    strcat(filespec, "/");
    strcat(filespec, fileList[filenum]);

    free(fileList);
    
    *result = 0;

    /* Check to see if the file was installed - if not pretend all is OK */
    if (headerGetEntry(h, RPMTAG_FILESTATES, &type, 
		 (void **) &fileStatesList, &count) && fileStatesList) {
	if (fileStatesList[filenum] == RPMFILE_STATE_NOTINSTALLED)
	    return 0;
    }

    if (lstat(filespec, &sb)) 
	return 1;

    if (S_ISDIR(sb.st_mode))
	flags &= ~(RPMVERIFY_MD5 | RPMVERIFY_FILESIZE | RPMVERIFY_MTIME | RPMVERIFY_LINKTO);
    else if (S_ISLNK(sb.st_mode))
	flags &= ~(RPMVERIFY_MD5 | RPMVERIFY_FILESIZE | RPMVERIFY_MTIME);
    else if (S_ISFIFO(sb.st_mode))
	flags &= ~(RPMVERIFY_MD5 | RPMVERIFY_FILESIZE | RPMVERIFY_MTIME | RPMVERIFY_LINKTO);
    else if (S_ISCHR(sb.st_mode))
	flags &= ~(RPMVERIFY_MD5 | RPMVERIFY_FILESIZE | RPMVERIFY_MTIME | RPMVERIFY_LINKTO);
    else if (S_ISBLK(sb.st_mode))
	flags &= ~(RPMVERIFY_MD5 | RPMVERIFY_FILESIZE | RPMVERIFY_MTIME | RPMVERIFY_LINKTO);
    else 
	flags &= ~(RPMVERIFY_LINKTO);

    if (flags & RPMVERIFY_MD5) {
	headerGetEntry(h, RPMTAG_FILEMD5S, &type, (void **) &md5List, &count);
	if (useBrokenMd5) {
	    rc = mdfileBroken(filespec, md5sum);
	} else {
	    rc = mdfile(filespec, md5sum);
	}

	if (rc || strcmp(md5sum, md5List[filenum]))
	    *result |= RPMVERIFY_MD5;
	free(md5List);
    } 
    if (flags & RPMVERIFY_LINKTO) {
	headerGetEntry(h, RPMTAG_FILELINKTOS, &type, (void **) &linktoList, &count);
	size = readlink(filespec, linkto, sizeof(linkto));
	if (size == -1)
	    *result |= RPMVERIFY_LINKTO;
	else 
	    linkto[size] = '\0';
	    if (strcmp(linkto, linktoList[filenum]))
		*result |= RPMVERIFY_LINKTO;
	free(linktoList);
    } 
    if (flags & RPMVERIFY_FILESIZE) {
	headerGetEntry(h, RPMTAG_FILESIZES, &type, (void **) &sizeList, &count);
	if (sizeList[filenum] != sb.st_size)
	    *result |= RPMVERIFY_FILESIZE;
    } 
    if (flags & RPMVERIFY_MODE) {
	if (modeList[filenum] != sb.st_mode)
	    *result |= RPMVERIFY_MODE;
    }
    if (flags & RPMVERIFY_RDEV) {
	headerGetEntry(h, RPMTAG_FILERDEVS, &type, (void **) &rdevList, &count);
	if (rdevList[filenum] != sb.st_rdev)
	    *result |= RPMVERIFY_RDEV;
    }
    if (flags & RPMVERIFY_MTIME) {
	headerGetEntry(h, RPMTAG_FILEMTIMES, &type, (void **) &mtimeList, &count);
	if (mtimeList[filenum] != sb.st_mtime)
	    *result |= RPMVERIFY_MTIME;
    }
    if (flags & RPMVERIFY_USER) {
	headerGetEntry(h, RPMTAG_FILEUIDS, &type, (void **) &uidList, &count);
	if (uidList[filenum] != sb.st_uid)
	    *result |= RPMVERIFY_USER;
    }
    if (flags & RPMVERIFY_GROUP) {
	headerGetEntry(h, RPMTAG_FILEGIDS, &type, (void **) &gidList, &count);
	if (gidList[filenum] != sb.st_gid)
	    *result |= RPMVERIFY_GROUP;
    }

    return 0;
}

int rpmVerifyScript(char * root, Header h, int err) {
    int out, fd;
    char * script;
    char * fn;
    char * tmpdir = rpmGetVar(RPMVAR_TMPPATH);
    int status;

    if (!headerGetEntry(h, RPMTAG_VERIFYSCRIPT, NULL, (void **) &script, 
			NULL)) {
	return 0;
    }

    if (rpmIsVerbose()) {
	out = err;
    } else {
	out = open("/dev/null", O_APPEND);
	if (out < 0) {
	    out = err;
	}
    }

    fn = alloca(strlen(tmpdir) + 20);
    sprintf(fn, "%s/rpm-%d.vscript", tmpdir, getpid());

    rpmMessage(RPMMESS_DEBUG, "verify script found - "
		"running from file %s\n", fn);

    fd = open(fn, O_CREAT | O_RDWR);
    unlink(fn);
    if (fd < 0) {
	rpmError(RPMERR_SCRIPT, "error creating file for verify script");
	return 1;
    }
    write(fd, SCRIPT_PATH, strlen(SCRIPT_PATH));
    write(fd, script, strlen(script));
    lseek(fd, 0, SEEK_SET);

    if (!fork()) {
	dup2(fd, 0);
	close(fd);

	if (err != 2) dup2(err, 2);
        if (out != 1) dup2(out, 1);

	/* make sure we don't close stdin/stderr/stdout by mistake! */
	if (err > 2) close (err);
	if (out > 2 && out != err) close (out);

	if (strcmp(root, "/")) {
	    rpmMessage(RPMMESS_DEBUG, "performing chroot(%s)\n", root);
	    chroot(root);
	    chdir("/");
	}

	if (rpmIsDebug())
	    execl("/bin/sh", "/bin/sh", "-x", "-s", NULL);
	else
	    execl("/bin/sh", "/bin/sh", "-s", NULL);
	exit(-1);
    }

    if (out > 2) close(out);
    if (err > 2) close(err);
    close(fd);
    if (!rpmIsVerbose()) close(out);

    wait(&status);

    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
	rpmError(RPMERR_SCRIPT, "execution of verify script failed");
	return 1;
    }

    return 0;
}
