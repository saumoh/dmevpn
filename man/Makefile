MAN5PAGES = opennhrp.conf.5
MAN8PAGES = opennhrp.8 opennhrpctl.8 opennhrp-script.8

install:
	$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man5 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) $(addprefix $(src)/,$(MAN5PAGES)) $(DESTDIR)$(MANDIR)/man5
	$(INSTALL) $(addprefix $(src)/,$(MAN8PAGES)) $(DESTDIR)$(MANDIR)/man8
