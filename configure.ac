dnl
dnl autoconf for Agents
dnl
dnl License: GNU General Public License (GPL)

dnl ===============================================
dnl Bootstrap 
dnl ===============================================
AC_PREREQ(2.63)

dnl Suggested structure:
dnl     information on the package
dnl     checks for programs
dnl     checks for libraries
dnl     checks for header files
dnl     checks for types
dnl     checks for structures
dnl     checks for compiler characteristics
dnl     checks for library functions
dnl     checks for system services

AC_INIT([sbd], 
	[1.2.1],
	[lmb@suse.com])
AC_CANONICAL_HOST
AC_CONFIG_AUX_DIR(.)
AC_CONFIG_HEADERS(config.h)
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([no])])
AM_INIT_AUTOMAKE
AM_PROG_CC_C_O

PKG_CHECK_MODULES(glib, [glib-2.0])
dnl PKG_CHECK_MODULES(libcoroipcc, [libcoroipcc])

dnl pacemaker > 1.1.8
PKG_CHECK_MODULES(pacemaker, [pacemaker, pacemaker-cib], HAVE_pacemaker=1, HAVE_pacemaker=0)

dnl pacemaker <= 1.1.8
PKG_CHECK_MODULES(pcmk, [pcmk, pcmk-cib], HAVE_pcmk=1, HAVE_pcmk=0)
PKG_CHECK_MODULES(libqb, [libqb])

CPPFLAGS="$CPPFLAGS -Werror"
if test $HAVE_pacemaker = 0 -a $HAVE_pcmk = 0; then
    AC_MSG_ERROR(No package 'pacemaker' found)
elif test $HAVE_pacemaker = 1; then
    CPPFLAGS="$CPPFLAGS $glib_CFLAGS $pacemaker_CFLAGS"
fi

PKG_CHECK_MODULES(libxml, [libxml-2.0])
CPPFLAGS="$CPPFLAGS $libxml_CFLAGS $libqb_CFLAGS"

dnl     checks for libraries
AC_CHECK_LIB(aio, io_setup, , missing="yes")
AC_CHECK_LIB(qb, qb_ipcs_connection_auth_set, , missing="yes")
AC_CHECK_LIB(cib, cib_new, , missing="yes")
AC_CHECK_LIB(crmcommon, set_crm_log_level, , missing="yes")
AC_CHECK_LIB(pe_status, pe_find_node, , missing="yes")
AC_CHECK_LIB(pe_rules, test_rule, , missing="yes")
AC_CHECK_LIB(crmcluster, crm_peer_init, , missing="yes")
AC_CHECK_LIB(uuid, uuid_unparse, , missing="yes")

dnl pacemaker >= 1.1.8
AC_CHECK_HEADERS(pacemaker/crm/cluster.h)
AC_CHECK_LIB(crmcommon, pcmk_strerror, , missing="yes")
AC_CHECK_LIB(cib, cib_apply_patch_event, , missing="yes")

if test "$missing" = "yes"; then
   AC_MSG_ERROR([Missing required libraries or functions.])
fi

AC_PATH_PROGS(POD2MAN, pod2man, pod2man)

AC_ARG_ENABLE([shared-disk],
[  --enable-shared-disk Turn on functionality that requires shared disk
     [default=yes]])

DISK=0
if test "x${enable_shared_disk}" != xno ; then
   DISK=1
fi
AC_DEFINE_UNQUOTED(SUPPORT_SHARED_DISK, $DISK, Turn on functionality that requires shared disk)
AM_CONDITIONAL(SUPPORT_SHARED_DISK, test "$DISK" = "1")

AC_MSG_NOTICE(Sanitizing prefix: ${prefix})
case $prefix in
  NONE)
	prefix=/usr
	dnl Fix default variables - "prefix" variable if not specified
	if test "$localstatedir" = "\${prefix}/var"; then
		localstatedir="/var"
	fi
	if test "$sysconfdir" = "\${prefix}/etc"; then
		sysconfdir="/etc"
	fi
	;;
esac

AC_MSG_NOTICE(Sanitizing exec_prefix: ${exec_prefix})
case $exec_prefix in
  dnl For consistency with Heartbeat, map NONE->$prefix
  NONE)	  exec_prefix=$prefix;;
  prefix) exec_prefix=$prefix;;
esac

dnl Expand autoconf variables so that we dont end up with '${prefix}'
dnl in #defines and python scripts
dnl NOTE: Autoconf deliberately leaves them unexpanded to allow
dnl    make exec_prefix=/foo install
dnl No longer being able to do this seems like no great loss to me...

eval prefix="`eval echo ${prefix}`"
eval exec_prefix="`eval echo ${exec_prefix}`"
eval bindir="`eval echo ${bindir}`"
eval sbindir="`eval echo ${sbindir}`"
eval libexecdir="`eval echo ${libexecdir}`"
eval datadir="`eval echo ${datadir}`"
eval sysconfdir="`eval echo ${sysconfdir}`"
eval sharedstatedir="`eval echo ${sharedstatedir}`"
eval localstatedir="`eval echo ${localstatedir}`"
eval libdir="`eval echo ${libdir}`"
eval includedir="`eval echo ${includedir}`"
eval oldincludedir="`eval echo ${oldincludedir}`"
eval infodir="`eval echo ${infodir}`"
eval mandir="`eval echo ${mandir}`"

dnl The Makefiles and shell scripts we output
AC_CONFIG_FILES([Makefile src/Makefile agent/Makefile man/Makefile src/sbd.service])

dnl Now process the entire list of files added by previous 
dnl  calls to AC_CONFIG_FILES()
AC_OUTPUT()
