
AC_PREREQ(2.59)
AC_INIT(pppoesk, 1.1)
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

CFLAGS="${CFLAGS} -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes"
AC_SUBST(CFLAGS)

# Check for endianness
AC_C_BIGENDIAN(
    [AC_MSG_ERROR([big endian, sorry but pppoesk will not work])],
    [AC_MSG_RESULT([little endian, fine])],
    [AC_MSG_ERROR([unknown endianess ?])]
    )
    

# Checks extra paths for headers and libraries
AC_MSG_NOTICE([checking extra paths for libpcap and libnet libraries])
for p in /usr/local /opt; do
    
    AC_MSG_CHECKING([for $p/include directory])
    if test -d $p/include; then
	AC_MSG_RESULT([yes])
	CPPFLAGS="${CPPFLAGS} -I$p/include/"
    else
	AC_MSG_RESULT([no])
    fi
    
    AC_MSG_CHECKING([for $p/lib directory])
    if test -d $p/lib; then
	AC_MSG_RESULT([yes])
	LDFLAGS="${LDFLAGS} -L$p/lib/"
    else
	AC_MSG_RESULT([no])
    fi
done
	    
# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([pcap_compile],
    [pcap],
    [],
    [AC_MSG_ERROR([Cannot find libpcap library !])],
    )

AC_SEARCH_LIBS([libnet_init], 
    [net],
    [],
    [AC_MSG_ERROR([Cannot find libnet library !])],
    )

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
