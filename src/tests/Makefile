export PERLLIB = ..

all:

.PHONY: check
check: test-utils test-sa-channel integration-tests

.PHONY: test-utils
test-utils:
	./test_utils.pl

.PHONY: test-sa-channel
test-sa-channel:
	./test_sa_channel_parser.pl

.PHONY: integration-tests
integration-tests:
	./create_testdb.pl
	./init_testdb.pl
	./print_testdb.pl > testdb.txt.new
	diff -u testdb.txt testdb.txt.new
	./test_greylist.pl

clean:
	rm -rf *~ proxytest_report.out test.cfg testdb.txt.new
