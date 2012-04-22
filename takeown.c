// vim:set ts=4 sw=4 sts=4 noet:
#define _GNU_SOURCE
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <grp.h>

// Compile time configuration:
// TAKEOWN_UMASK is the umask() argument
// TAKEOWN_GID (optional) is the gid to chown created files to
// TAKEOWN_GROUP (optional) is the group name to chown created files to
// TAKEOWN_JAIL (optional) is the directory (without trailing slash) to restrict takeown to

#define xstr(s) str(s)
#define str(s) #s

#ifndef TAKEOWN_UMASK
#	define TAKEOWN_UMASK 077
#endif

#ifdef TAKEOWN_JAIL
#	define TAKEOWN_ACTUAL_JAIL xstr(TAKEOWN_JAIL)
#endif

#ifdef TAKEOWN_GROUP
#	define TAKEOWN_ACTUAL_GROUP xstr(TAKEOWN_GROUP)
#endif

int suid = 0;
struct group *grp = NULL;
uid_t owner = 0;
char * cwd = NULL;

char * gettmppath(const char * filename) {
	size_t len = strlen(filename);
	char * result = (char *) malloc(sizeof(char)*(len+2));
	strncpy(result, filename, len);
	result[len] = '~';
	result[len+1] = '\0';
	return result;
}

int contains_two_dots(const char * path) {
	int state = 1;
	int i = 0;
	while (path[i]) {
		switch (state) {
			case 0: // no danger
				if (path[i] == '/') state = 1;
				break;
			case 1: // beginning of entry name
				if (path[i] == '.') state = 2;
				else if (path[i] == '/') state = 1;
				else state = 0;
				break;
			case 2: // entry name begins with a dot
				if (path[i] == '.') state = 3;
				else state = 0;
				break;
			case 3: // entry name begins with two dots
				if (path[i] == '/') state = 4;
				else state = 0;
				break;
			case 4: // entry contains two dots
				break;
		}
		++i;
	}
	if (state == 3 || state == 4) {
		// path contains two dots (state=4) or ends in two dots (state=3)
		return 1;
	}
	return 0;
}

char * ensure_jail(const char * filename, const char * jail) {
	if (cwd == NULL)
		cwd = get_current_dir_name();

	if (contains_two_dots(filename)) {
		warnx("Filename `%s' contains too many dots", filename);
		return NULL;
	}
	if (contains_two_dots(cwd)) {
		warnx("Current working directory `%s' contains too many dots", cwd);
		return NULL;
	}

	if (filename[0] == '/') {
		// check if jail is a prefix of filename.
		// find first index on which filename and jail differ
		int i = 0;
		while (filename[i] && jail[i]) {
			if (filename[i] != jail[i]) break;
			++i;
		}
		// is jail a prefix of filename?
		if (!jail[i]) {
			// jail is a prefix of filename.
			if (filename[i] == '/') {
				// good enough.
				return strdup(filename);
			}
		}
		warnx("`%s' is not inside the jail (`%s')", filename, jail);
		return NULL;
	} else {
		// is jail a prefix of cwd?
		if (cwd[0] != '/') {
			warnx("Current working directory is not an absolute path: `%s'", cwd);
			return NULL;
		}
		int i = 0;
		while (cwd[i] && jail[i]) {
			if (cwd[i] != jail[i]) break;
			++i;
		}
		if (!jail[i] && !cwd[i]) {
			// abs = jail+'/'+filename
			size_t jaillength = strlen(jail);
			size_t namelength = strlen(filename);
			char * abs = (char *) malloc(sizeof(char)*(jaillength+1+namelength+1));
			strncpy(abs, jail, jaillength);
			abs[jaillength] = '/';
			strncpy(abs+jaillength+1, filename, namelength);
			abs[jaillength+1+namelength] = '\0';
			return abs;
		}
		if (!jail[i] && cwd[i] == '/') {
			// abs = jail + part of cwd relative to jail + filename
			char * partcwd = cwd + i;
			size_t jaillength = strlen(jail);
			size_t cwdlength = strlen(partcwd);
			size_t namelength = strlen(filename);
			char * abs = (char *) malloc(jaillength + cwdlength + 1 + namelength);
			strncpy(abs, jail, jaillength);
			strncpy(abs+jaillength, partcwd, cwdlength);
			abs[jaillength+cwdlength] = '/';
			strncpy(abs+jaillength+cwdlength+1, filename, namelength);
			abs[jaillength+cwdlength+1+namelength] = '\0';
			return abs;
		}
		warnx("Current working directory is outside the jail: `%s'", cwd);
		return NULL;
	}
}

void takeown(const char * filename) {
	struct stat statbuf;
	FILE * fd = fopen(filename, "r");
	if (fd == NULL) {
		warn("Could not open %s for reading", filename);
		return;
	}
	if (-1 == fstat(fileno(fd), &statbuf)) {
		warn("Could not stat %s", filename);
		goto out2;
	}
	if (!S_ISREG(statbuf.st_mode)) {
		warnx("Cowardly refusing to take ownership of `%s', as it is not a regular file", filename);
		goto out2;
	}
	char * tmppath = gettmppath(filename);
	if (-1 == rename(filename, tmppath)) {
		warn("Could not rename `%s' to `%s'", filename, tmppath);
		goto out3;
	}
	FILE * fd2 = fopen(filename, "w");
	if (fd == NULL) {
		warn("Could not open `%s' for writing", filename);
		goto out3;
	}
	const int BUFLEN = 4096;
	void *buf = malloc(BUFLEN);
	while (1) {
		size_t bytesread = fread(buf, 1, BUFLEN, fd);
		if (bytesread == 0)
			break;

		fwrite(buf, 1, bytesread, fd2);
	}
	if (-1 == unlink(tmppath)) {
		warn("Could not unlink `%s'", tmppath);
		goto out4;
	}
	if (grp != NULL) {
		if (-1 == fchown(fileno(fd2), owner, grp->gr_gid)) {
			warn("Could not change ownership of `%s'", filename);
			goto out4;
		}
	}
out4:
	fclose(fd2);
out3:
	free(tmppath);
out2:
	fclose(fd);
}

void usage(const char * progname) {
	printf("Usage: %s file1 [file2 [...]]\n"
		   "Take ownership of the given files.\n",
		   progname);
#ifdef TAKEOWN_ACTUAL_JAIL
	printf("Usage is restricted to files within " TAKEOWN_ACTUAL_JAIL ".\n");
#endif
}

int main(int argc, char ** argv) {
	int i;
	for (i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "--")) {
			++i;
			break;
		}
		if (argv[i][0] != '-') {
			break;
		}
		usage(argv[0]);
		return 1;
	}
	if (i >= argc) {
		usage(argv[0]);
		return 1;
	}
	uid_t ruid = getuid();
	uid_t euid = geteuid();
	if (ruid == euid) {
		suid = 0;
	} else {
		suid = 1;
	}
	owner = euid;
#ifdef TAKEOWN_GID
	grp = getgrgid(TAKEOWN_GID);
#else
#ifdef TAKEOWN_ACTUAL_GROUP
	grp = getgrnam(TAKEOWN_ACTUAL_GROUP);
#endif // TAKEOWN_ACTUAL_GROUP
#endif // TAKEOWN_GID

	mode_t oldmask = umask(TAKEOWN_UMASK);
	while (i < argc) {
#ifdef TAKEOWN_ACTUAL_JAIL
		char * filename = ensure_jail(argv[i], TAKEOWN_ACTUAL_JAIL);
		if (filename == NULL) {
			++i;
			continue;
		}
#else
		char * filename = strdup(argv[i]);
#endif
		takeown(filename);
		free(filename);
		++i;
	}
	umask(oldmask);
	return 0;
}
