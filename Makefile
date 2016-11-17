##
# Building opennhrp

PACKAGE := opennhrp
VERSION := 0.14.1

##
# Default directories

DESTDIR=
SBINDIR=/usr/sbin
CONFDIR=/etc/opennhrp
MANDIR=/usr/share/man
DOCDIR=/usr/share/doc/opennhrp
STATEDIR=/var/run

export DESTDIR SBINDIR CONFDIR MANDIR DOCDIR STATEDIR

##
# Top-level rules and targets

targets		:= nhrp/ etc/ man/

##
# Include all rules and stuff

include Make.rules

##
# Top-level targets

install:
	$(INSTALLDIR) $(DESTDIR)$(DOCDIR)
	$(INSTALL) README $(DESTDIR)$(DOCDIR)
