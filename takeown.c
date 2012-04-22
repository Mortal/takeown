// vim:set ts=4 sw=4 sts=4 noet:
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>

char * gettmppath(const char * filename) {
	size_t len = strlen(filename);
	char * result = (char *) malloc(sizeof(char)*(len+2));
	strncpy(result, filename, len);
	result[len] = '~';
	result[len+1] = '\0';
	return result;
}

int takeown(const char * filename) {
	int result = 0;
	struct stat statbuf;
	FILE * fd = fopen(filename, "r");
	if (fd == NULL) {
		warn("Could not open %s for reading", filename);
		if (errno != ENOENT)
			result = 1;
		goto out1;
	}
	result = 1;
	if (-1 == fstat(fileno(fd), &statbuf)) {
		warn("Could not stat %s", filename);
		goto out2;
	}
	if (!S_ISREG(statbuf.st_mode)) {
		warnx("Cowardly refusing to take ownership of %s, as it is not a regular file", filename);
		goto out2;
	}
	char * tmppath = gettmppath(filename);
	if (-1 == rename(filename, tmppath)) {
		warn("Could not rename %s to %s", filename, tmppath);
		goto out3;
	}
	FILE * fd2 = fopen(filename, "w");
	if (fd == NULL) {
		warn("Could not open %s for writing", filename);
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
		warn("Could not unlink %s", tmppath);
		goto out4;
	}
	result = 1;
out4:
	fclose(fd2);
out3:
	free(tmppath);
out2:
	fclose(fd);
out1:
	return result;
}

void usage(const char * progname) {
	printf("Usage: %s file1 [file2 [...]]\n"
		   "Take ownership of the given files.\n",
		   progname);
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
	mode_t oldmask = umask(077);
	int successes = 0;
	while (i < argc) {
		successes += takeown(argv[i]);
		++i;
	}
	umask(oldmask);
	if (!successes) {
		usage(argv[0]);
		return 1;
	}
	return 0;
}
