#export TESTDB = "Proxmox_testdb"

export PERLLIB = ..

all:

check:
	./create_testdb.pl
	./init_testdb.pl
	./print_testdb.pl > testdb.txt.new
	diff -u testdb.txt testdb.txt.new
	./test_greylist.pl
	./test_sa_channel_parser.pl

#	test_config.pl		\
#	test_mimetype.pl	\
#	test_proxy.pl		\
#	test_unpack.pl


clean:
	rm -rf *~ proxytest_report.out test.cfg testdb.txt.new
