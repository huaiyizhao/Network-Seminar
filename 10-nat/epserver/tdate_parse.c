
#include <sys/types.h>

#include <ctype.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct strlong {
	char* s;
	long l;
};


	static void
pound_case( char* str )
{
	for ( ; *str != '\0'; ++str )
	{
		if ( isupper( *str ) )
			*str = tolower( *str );
	}
}

	static int
strlong_compare( v1, v2 )
	char* v1;
	char* v2;
{
	return strcmp( ((struct strlong*) v1)->s, ((struct strlong*) v2)->s );
}


	static int
strlong_search( char* str, struct strlong* tab, int n, long* lP )
{
	int i, h, l, r;

	l = 0;
	h = n - 1;
	for (;;)
	{
		i = ( h + l ) / 2;
		r = strcmp( str, tab[i].s );
		if ( r < 0 )
			h = i - 1;
		else if ( r > 0 )
			l = i + 1;
		else
		{
			*lP = tab[i].l;
			return 1;
		}
		if ( h < l )
			return 0;
	}
}


	static int
scan_wday( char* str_wday, long* tm_wdayP )
{
	static struct strlong wday_tab[] = {
		{ "sun", 0 }, { "sunday", 0 },
		{ "mon", 1 }, { "monday", 1 },
		{ "tue", 2 }, { "tuesday", 2 },
		{ "wed", 3 }, { "wednesday", 3 },
		{ "thu", 4 }, { "thursday", 4 },
		{ "fri", 5 }, { "friday", 5 },
		{ "sat", 6 }, { "saturday", 6 },
	};
	static int sorted = 0;

	if ( ! sorted )
	{
		(void) qsort(
				wday_tab, sizeof(wday_tab)/sizeof(struct strlong),
				sizeof(struct strlong), strlong_compare );
		sorted = 1;
	}
	pound_case( str_wday );
	return strlong_search( 
			str_wday, wday_tab, sizeof(wday_tab)/sizeof(struct strlong), tm_wdayP );
}


	static int
scan_mon( char* str_mon, long* tm_monP )
{
	static struct strlong mon_tab[] = {
		{ "jan", 0 }, { "january", 0 },
		{ "feb", 1 }, { "february", 1 },
		{ "mar", 2 }, { "march", 2 },
		{ "apr", 3 }, { "april", 3 },
		{ "may", 4 },
		{ "jun", 5 }, { "june", 5 },
		{ "jul", 6 }, { "july", 6 },
		{ "aug", 7 }, { "august", 7 },
		{ "sep", 8 }, { "september", 8 },
		{ "oct", 9 }, { "october", 9 },
		{ "nov", 10 }, { "november", 10 },
		{ "dec", 11 }, { "december", 11 },
	};
	static int sorted = 0;

	if ( ! sorted )
	{
		(void) qsort(
				mon_tab, sizeof(mon_tab)/sizeof(struct strlong),
				sizeof(struct strlong), strlong_compare );
		sorted = 1;
	}
	pound_case( str_mon );
	return strlong_search( 
			str_mon, mon_tab, sizeof(mon_tab)/sizeof(struct strlong), tm_monP );
}


	static int
is_leap( int year )
{
	return year % 400? ( year % 100 ? ( year % 4 ? 0 : 1 ) : 0 ) : 1;
}


/* Basically the same as mktime(). */
	static time_t
tm_to_time( struct tm* tmP )
{
	time_t t;
	static int monthtab[12] = {
		0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

	/* Years since epoch, converted to days. */
	t = ( tmP->tm_year - 70 ) * 365;
	/* Leap days for previous years. */
	t += ( tmP->tm_year - 1 - 68 ) / 4; /* -1: don't count this year */
	/* 100-divisible year is not a leap year 
	   400-divisible year is a leap year */
	if (tmP->tm_year > 200)
		t -= (tmP->tm_year - 1 - 100) / 100;
	if (tmP->tm_year > 500)
		t += (tmP->tm_year - 1 - 100) / 400;

	/* Days for the beginning of this month. */
	t += monthtab[tmP->tm_mon];
	/* Leap day for this year. */
	if ( tmP->tm_mon >= 2 && is_leap( tmP->tm_year ) )
		++t;
	/* Days since the beginning of this month. */
	t += tmP->tm_mday - 1;	/* 1-based field */
	/* Hours, minutes, and seconds. */
	t = t * 24 + tmP->tm_hour;
	t = t * 60 + tmP->tm_min;
	t = t * 60 + tmP->tm_sec;

	return t;
}


	time_t
httpdate_to_timet( const char* str )
{
	struct tm tm;
	const char* cp;
	char str_mon[500], str_wday[500];
	int tm_sec, tm_min, tm_hour, tm_mday, tm_year;
	long tm_mon, tm_wday;
	time_t t;

	/* Initialize. */
	memset( (char*) &tm, 0, sizeof(struct tm) );

	/* Skip initial whitespace ourselves - sscanf is clumsy at this. */
	for ( cp = str; *cp == ' ' || *cp == '\t'; ++cp )
		;

	/* And do the sscanfs.  WARNING: you can add more formats here,
	 ** but be careful!  You can easily screw up the parsing of existing
	 ** formats when you add new ones.  The order is important.
	 */

	/* DD-mth-YY HH:MM:SS GMT */
	if ( sscanf( cp, "%d-%[a-zA-Z]-%d %d:%d:%d GMT",
				&tm_mday, str_mon, &tm_year, &tm_hour, &tm_min,
				&tm_sec ) == 6 &&
			scan_mon( str_mon, &tm_mon ) )
	{
		tm.tm_mday = tm_mday;
		tm.tm_mon = tm_mon;
		tm.tm_year = tm_year;
		tm.tm_hour = tm_hour;
		tm.tm_min = tm_min;
		tm.tm_sec = tm_sec;
	}

	/* DD mth YY HH:MM:SS GMT */
	else if ( sscanf( cp, "%d %[a-zA-Z] %d %d:%d:%d GMT",
				&tm_mday, str_mon, &tm_year, &tm_hour, &tm_min,
				&tm_sec) == 6 &&
			scan_mon( str_mon, &tm_mon ) )
	{
		tm.tm_mday = tm_mday;
		tm.tm_mon = tm_mon;
		tm.tm_year = tm_year;
		tm.tm_hour = tm_hour;
		tm.tm_min = tm_min;
		tm.tm_sec = tm_sec;
	}

	/* HH:MM:SS GMT DD-mth-YY */
	else if ( sscanf( cp, "%d:%d:%d GMT %d-%[a-zA-Z]-%d",
				&tm_hour, &tm_min, &tm_sec, &tm_mday, str_mon,
				&tm_year ) == 6 &&
			scan_mon( str_mon, &tm_mon ) )
	{
		tm.tm_hour = tm_hour;
		tm.tm_min = tm_min;
		tm.tm_sec = tm_sec;
		tm.tm_mday = tm_mday;
		tm.tm_mon = tm_mon;
		tm.tm_year = tm_year;
	}

	/* HH:MM:SS GMT DD mth YY */
	else if ( sscanf( cp, "%d:%d:%d GMT %d %[a-zA-Z] %d",
				&tm_hour, &tm_min, &tm_sec, &tm_mday, str_mon,
				&tm_year ) == 6 &&
			scan_mon( str_mon, &tm_mon ) )
	{
		tm.tm_hour = tm_hour;
		tm.tm_min = tm_min;
		tm.tm_sec = tm_sec;
		tm.tm_mday = tm_mday;
		tm.tm_mon = tm_mon;
		tm.tm_year = tm_year;
	}

	/* wdy, DD-mth-YY HH:MM:SS GMT */
	else if ( sscanf( cp, "%[a-zA-Z], %d-%[a-zA-Z]-%d %d:%d:%d GMT",
				str_wday, &tm_mday, str_mon, &tm_year, &tm_hour, &tm_min,
				&tm_sec ) == 7 &&
			scan_wday( str_wday, &tm_wday ) &&
			scan_mon( str_mon, &tm_mon ) )
	{
		tm.tm_wday = tm_wday;
		tm.tm_mday = tm_mday;
		tm.tm_mon = tm_mon;
		tm.tm_year = tm_year;
		tm.tm_hour = tm_hour;
		tm.tm_min = tm_min;
		tm.tm_sec = tm_sec;
	}

	/* wdy, DD mth YY HH:MM:SS GMT */
	else if ( sscanf( cp, "%[a-zA-Z], %d %[a-zA-Z] %d %d:%d:%d GMT",
				str_wday, &tm_mday, str_mon, &tm_year, &tm_hour, &tm_min,
				&tm_sec ) == 7 &&
			scan_wday( str_wday, &tm_wday ) &&
			scan_mon( str_mon, &tm_mon ) )
	{
		tm.tm_wday = tm_wday;
		tm.tm_mday = tm_mday;
		tm.tm_mon = tm_mon;
		tm.tm_year = tm_year;
		tm.tm_hour = tm_hour;
		tm.tm_min = tm_min;
		tm.tm_sec = tm_sec;
	}

	/* wdy mth DD HH:MM:SS GMT YY */
	else if ( sscanf( cp, "%[a-zA-Z] %[a-zA-Z] %d %d:%d:%d GMT %d",
				str_wday, str_mon, &tm_mday, &tm_hour, &tm_min, &tm_sec,
				&tm_year ) == 7 &&
			scan_wday( str_wday, &tm_wday ) &&
			scan_mon( str_mon, &tm_mon ) )
	{
		tm.tm_wday = tm_wday;
		tm.tm_mon = tm_mon;
		tm.tm_mday = tm_mday;
		tm.tm_hour = tm_hour;
		tm.tm_min = tm_min;
		tm.tm_sec = tm_sec;
		tm.tm_year = tm_year;
	}
	else
		return (time_t) -1;

	if ( tm.tm_year > 1900 )
		tm.tm_year -= 1900;
	else if ( tm.tm_year < 70 )
		tm.tm_year += 100;

	t = tm_to_time( &tm );

	return t;
}

/* 
   Convert 't' (in time_t format) into the HTTP date format
   <input parameters>
t:      input (epoch-based time)
str:    output string that holds the HTTP date strinng
strlen: the buffer size of str

<return value>
0 : in case of successful conversion
-1 : otherwise
by KyoungSoo Park 
*/
	int
timet_to_httpdate(time_t t, char* str, int strlen )
{
	static const char* day_of_week[] = {"Sun", "Mon","Tue", 
		"Wed", "Thu", "Fri", "Sat"};

	static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	struct tm gm;

	if (gmtime_r(&t, &gm) == NULL)
		return(-1);

	/* example date: "Sat, 26 Mar 2011 05:53:57 GMT" */
	if (snprintf(str, strlen, 
				"%s, %02d %s %4d %02d:%02d:%02d GMT",
				day_of_week[gm.tm_wday],
				gm.tm_mday,
				months[gm.tm_mon],
				gm.tm_year + 1900,
				gm.tm_hour,
				gm.tm_min,
				gm.tm_sec) == strlen)
		/* probably str has an insufficient buffer size */
		return (-1);
	return(0);
}