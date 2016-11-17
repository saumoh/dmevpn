ETCFILES := opennhrp.conf opennhrp-script racoon-ph1down.sh racoon-ph1dead.sh

install:
	$(INSTALLDIR) $(DESTDIR)$(CONFDIR)
	$(INSTALL) $(addprefix $(src)/,$(ETCFILES)) $(DESTDIR)$(CONFDIR)
