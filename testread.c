#include <stdio.h>
#include <utmp.h>

int main()
{
	struct utmp entry;
	while (fread(&entry, sizeof(struct utmp), 1, stdin)) {
		printf("%s\n", entry.ut_host);
	}
	return 0;
}
