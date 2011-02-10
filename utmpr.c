#include <stdio.h>
#include <inttypes.h>
#include <utmp.h>

int main()
{
	struct utmp entry;
	while (fread(&entry, sizeof(struct utmp), 1, stdin)) {
		char ip[16];
		if (0) //TODO: determine how to figure out of it's an ipv6. entries 1 2 and 3 are zero perhaps?
			ip[0] = 'a'; //TODO: format ipv6 address
		else
			sprintf(ip, "%d.%d.%d.%d",
				(entry.ut_addr_v6[0] >> 0x0) & 0xFF,
				(entry.ut_addr_v6[0] >> 0x8) & 0xFF,
				(entry.ut_addr_v6[0] >> 0x10) & 0xFF,
				(entry.ut_addr_v6[0] >> 0x18) & 0xFF);

		#if __WORDSIZE == 64 && defined __WORDSIZE_COMPAT32
		char *formatString = "%hd\t%d\t%s\t%s\t%s\t%s\t%hd\t%hd\t%"PRId32"\t%"PRId32"\t%"PRId32"\t%s\n";
		#else
		char *formatString = "%hd\t%d\t%s\t%s\t%s\t%s\t%hd\t%hd\t%ld\t%ld\t%ld\t%s\n";
		#endif
		printf(formatString, entry.ut_type, entry.ut_pid, entry.ut_line,
				     entry.ut_id, entry.ut_user, entry.ut_host,
				     entry.ut_exit.e_termination, entry.ut_exit.e_exit,
				     entry.ut_session, entry.ut_tv.tv_sec,
				     entry.ut_tv.tv_usec, ip);		
	}
	return 0;
}
