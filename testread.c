#include <stdio.h>
#include <utmp.h>

int main()
{
	struct utmp entry;
	while (fread(&entry, sizeof(struct utmp), 1, stdin)) {
		#if __WORDSIZE == 64 && defined __WORDSIZE_COMPAT32
		char *formatString = "%hd\t%d\t%s\t%s\t%s\t%s\t%hd\t%hd\t%d\t%d\t%d\t%s\n";
		#else
		char *formatString = "%hd\t%d\t%s\t%s\t%s\t%s\t%hd\t%hd\t%ld\t%ld\t%ld\t%s\n"
		#endif
		printf(formatString, entry.ut_type, entry.ut_pid, entry.ut_line,
				     entry.ut_id, entry.ut_user, entry.ut_host,
				     entry.ut_exit.e_termination, entry.ut_exit.e_exit,
				     entry.ut_session, entry.ut_tv.tv_sec,
				     entry.ut_tv.tv_usec, "IPADDRESS");
	}
	return 0;
}
