# this requires package pmg-doc-generator
export NOVIEW=1
include /usr/share/pmg-doc-generator/pmg-doc-generator.mk

DESTDIR=

PERL5DIR=${DESTDIR}/usr/share/perl5
DOCDIR=${DESTDIR}/usr/share/doc/pmg-api/
BASHCOMPLDIR=${DESTDIR}/usr/share/bash-completion/completions/

SERVICES = pmgdaemon pmgproxy pmgtunnel pmgmirror
CLITOOLS = pmgdb pmgconfig pmgperf pmgcm pmgqm pmgreport pmgversion pmgupgrade pmgsubscription pmgbackup
CLISCRIPTS = pmg-smtp-filter pmgsh pmgpolicy pmgbanner pmg-system-report
CRONSCRIPTS = pmg-hourly pmg-daily

CLI_CLASSES = $(addprefix PMG/CLI/, $(addsuffix .pm, ${CLITOOLS}))
SERVICE_CLASSES = $(addprefix PMG/Service/, $(addsuffix .pm, ${SERVICES}))
SERVICE_UNITS = $(addprefix debian/, $(addsuffix .service, ${SERVICES}))
TIMER_UNITS = $(addprefix debian/, $(addsuffix .timer, ${CRONSCRIPTS} pmgspamreport pmgreport))

CLI_BINARIES = $(addprefix bin/, ${CLITOOLS} ${CLISCRIPTS} ${CRONSCRIPTS})
CLI_MANS = $(addsuffix .1, ${CLITOOLS}) pmgsh.1 pmg-system-report.1


SERVICE_MANS = $(addsuffix .8, ${SERVICES}) pmg-smtp-filter.8 pmgpolicy.8
CONF_MANS= pmg.conf.5 cluster.conf.5

TEMPLATES =				\
	fetchmailrc.tt			\
	pmgreport.tt			\
	spamreport-verbose.tt		\
	spamreport-short.tt		\
	main.cf.in			\
	main.cf.in.demo			\
	master.cf.in			\
	master.cf.in.demo		\
	init.pre.in			\
	local.cf.in			\
	v310.pre.in			\
	v320.pre.in			\
	razor-agent.conf.in		\
	freshclam.conf.in		\
	clamd.conf.in 			\
	postgresql.conf.in		\
	pg_hba.conf.in

TEMPLATES_FILES = $(addprefix templates/, ${TEMPLATES})

LIBSOURCES =				\
	PMG/pmgcfg.pm			\
	PMG/RESTEnvironment.pm		\
	PMG/Utils.pm			\
	PMG/MIMEUtils.pm		\
	PMG/HTMLMail.pm			\
	PMG/ModGroup.pm			\
	PMG/SMTPPrinter.pm		\
	PMG/Config.pm			\
	PMG/Cluster.pm			\
	PMG/ClusterConfig.pm		\
	PMG/HTTPServer.pm		\
	PMG/Ticket.pm			\
	PMG/AccessControl.pm		\
	PMG/AtomicFile.pm		\
	PMG/MailQueue.pm		\
	PMG/Postfix.pm			\
	PMG/SMTP.pm			\
	PMG/Unpack.pm			\
	PMG/Backup.pm			\
	PMG/RuleCache.pm		\
	PMG/Statistic.pm		\
	PMG/UserConfig.pm		\
	PMG/Fetchmail.pm		\
	PMG/LDAPConfig.pm		\
	PMG/LDAPSet.pm			\
	PMG/LDAPCache.pm		\
	PMG/DBTools.pm			\
	PMG/DKIMSign.pm			\
	PMG/Quarantine.pm		\
	PMG/Report.pm			\
	PMG/SACustom.pm			\
	PMG/RuleDB/Group.pm		\
	PMG/RuleDB/Rule.pm		\
	PMG/RuleDB/Object.pm		\
	PMG/RuleDB/Quarantine.pm	\
	PMG/RuleDB/WhoRegex.pm		\
	PMG/RuleDB/IPAddress.pm		\
	PMG/RuleDB/IPNet.pm		\
	PMG/RuleDB/ModField.pm		\
	PMG/RuleDB/MatchFilename.pm	\
	PMG/RuleDB/ReceiverRegex.pm	\
	PMG/RuleDB/EMail.pm		\
	PMG/RuleDB/Receiver.pm		\
	PMG/RuleDB/Domain.pm		\
	PMG/RuleDB/ReceiverDomain.pm	\
	PMG/RuleDB/LDAP.pm		\
	PMG/RuleDB/LDAPUser.pm		\
	PMG/RuleDB/TimeFrame.pm		\
	PMG/RuleDB/MatchField.pm	\
	PMG/RuleDB/ContentTypeFilter.pm	\
	PMG/RuleDB/ArchiveFilter.pm	\
	PMG/RuleDB/Spam.pm		\
	PMG/RuleDB/Virus.pm		\
	PMG/RuleDB/ReportSpam.pm	\
	PMG/RuleDB/Remove.pm		\
	PMG/RuleDB/Attach.pm		\
	PMG/RuleDB/BCC.pm		\
	PMG/RuleDB/Counter.pm		\
	PMG/RuleDB/Notify.pm		\
	PMG/RuleDB/Disclaimer.pm	\
	PMG/RuleDB/Accept.pm		\
	PMG/RuleDB/Block.pm		\
	PMG/RuleDB.pm			\
	${CLI_CLASSES} 			\
	${SERVICE_CLASSES}		\
	PMG/API2/Subscription.pm	\
	PMG/API2/APT.pm             	\
	PMG/API2/Network.pm             \
	PMG/API2/Services.pm		\
	PMG/API2/Tasks.pm		\
	PMG/API2/LDAP.pm		\
	PMG/API2/DestinationTLSPolicy.pm\
	PMG/API2/Domains.pm		\
	PMG/API2/DKIMSignDomains.pm	\
	PMG/API2/DKIMSign.pm		\
	PMG/API2/Fetchmail.pm		\
	PMG/API2/Users.pm		\
	PMG/API2/Transport.pm		\
	PMG/API2/MyNetworks.pm		\
	PMG/API2/MimeTypes.pm		\
	PMG/API2/Config.pm		\
	PMG/API2/Cluster.pm		\
	PMG/API2/ClamAV.pm		\
	PMG/API2/SpamAssassin.pm	\
	PMG/API2/SACustom.pm		\
	PMG/API2/Statistics.pm		\
	PMG/API2/MailTracker.pm		\
	PMG/API2/Backup.pm		\
	PMG/API2/Nodes.pm		\
	PMG/API2/Postfix.pm		\
	PMG/API2/Quarantine.pm		\
	PMG/API2/AccessControl.pm	\
	PMG/API2/ObjectGroupHelpers.pm	\
	PMG/API2/Rules.pm		\
	PMG/API2/RuleDB.pm		\
	PMG/API2/SMTPWhitelist.pm	\
	PMG/API2/Who.pm			\
	PMG/API2/When.pm		\
	PMG/API2/What.pm		\
	PMG/API2/Action.pm		\
	PMG/API2.pm

SOURCES = ${LIBSOURCES} ${CLI_BINARIES} ${TEMPLATES_FILES} ${CONF_MANS} ${CLI_MANS} ${SERVICE_MANS} ${SERVICE_UNITS} ${TIMER_UNITS} pmg-sources.list pmg-apt.conf pmg-initramfs.conf

all: ${SOURCES}

PMG/pmgcfg.pm: PMG/pmgcfg.pm.in
	sed -e s/@VERSION@/${PMGVERSION}/ -e s/@PMGRELEASE@/${PMGRELEASE}/ -e s/@PACKAGE@/${PACKAGE}/ -e s/@REPOID@/${REPOID}/ $< >$@.tmp
	mv $@.tmp $@

%.bash-completion:
	perl -I. -T -e "use PMG::CLI::$*; PMG::CLI::$*->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

%.service-bash-completion:
	perl -I. -T -e "use PMG::Service::$*; PMG::Service::$*->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

install: ${SOURCES} $(addsuffix .service-bash-completion, ${SERVICES}) $(addsuffix .bash-completion, ${CLITOOLS}) 
	for i in ${SERVICES}; do perl -I. -T -e "use PMG::Service::$$i; PMG::Service::$$i->verify_api();"; done
	for i in ${CLITOOLS}; do perl -I. -T -e "use PMG::CLI::$$i; PMG::CLI::$$i->verify_api();"; done
	perl -I. bin/pmgsh verifyapi
	install -d -m 0755 ${DESTDIR}/usr/bin
	install -d -m 0755 -o www-data -g www-data ${DESTDIR}/var/log/pmgproxy
	install -d -m 0755 ${DOCDIR}
	# TODO: is there a better location ?
	install -m 0644 favicon.ico ${DOCDIR}
	install -D -m 0644 pmg-apt.conf ${DESTDIR}/etc/apt/apt.conf.d/75pmgconf
	install -D -m 0644 pmg-sources.list ${DESTDIR}/etc/apt/sources.list.d/pmg-enterprise.list
	for i in ${LIBSOURCES}; do install -D -m 0644 $$i ${PERL5DIR}/$$i; done
	for i in ${SERVICES}; do install -D -m 0644 PMG/Service/$$i.pm ${PERL5DIR}/PMG/Service/$$i.pm; done
	for i in ${SERVICES}; do install -m 0755 bin/$$i ${DESTDIR}/usr/bin; done
	for i in ${SERVICES}; do install -m 0644 -D $$i.service-bash-completion ${BASHCOMPLDIR}/$$i; done
	for i in ${CLITOOLS}; do install -D -m 0644 PMG/CLI/$$i.pm ${PERL5DIR}/PMG/CLI/$$i.pm; done
	for i in ${CLITOOLS}; do install -D -m 0755 bin/$$i ${DESTDIR}/usr/bin/$$i; done
	for i in ${CLITOOLS}; do install -D -m 0644 $$i.bash-completion ${BASHCOMPLDIR}/$$i; done
	for i in ${CLISCRIPTS}; do install -D -m 0755 bin/$$i ${DESTDIR}/usr/bin/$$i; done
	for i in ${TEMPLATES}; do install -D -m 0644 templates/$$i ${DESTDIR}/var/lib/pmg/templates/$$i; done
	for i in ${CLI_MANS}; do install -D -m 0644 $$i ${DESTDIR}/usr/share/man/man1/$$i; done
	for i in ${CONF_MANS}; do install -D -m 0644 $$i ${DESTDIR}/usr/share/man/man5/$$i; done
	for i in ${SERVICE_MANS}; do install -D -m 0644 $$i ${DESTDIR}/usr/share/man/man8/$$i; done
	for i in ${CRONSCRIPTS}; do install -D -m 0755 bin/$$i ${DESTDIR}/usr/lib/pmg/bin/$$i; done
	install -d -m 0755 ${DESTDIR}/lib/systemd/system
	for i in ${TIMER_UNITS}; do install -m 0644 $$i ${DESTDIR}/lib/systemd/system/; done
	install -D -m 0644 pmg-initramfs.conf ${DESTDIR}/etc/initramfs-tools/conf.d/pmg-initramfs.conf

.PHONY: check
check:
	make -C tests check

.PHONY: clean
clean:
	make cleanup-docgen
	make -C tests clean
	rm -rf ${CONF_MANS} *.bash-completion *.service-bash-completion
	if test -d .git; then  rm -f PMG/pmgcfg.pm; fi
	find . -name '*~' -exec rm {} ';'

%.1: bin/%
	rm -f $@
	podselect $< |pod2man -n $(notdir $*) -s 1 -r ${PKGVER} -c"Proxmox Documentation" >$@.tmp
	mv $@.tmp $@
