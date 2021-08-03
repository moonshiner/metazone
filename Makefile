#
# LM: 2021-08-03 14:29:13-07:00
# Shawn Instenes <sinstenes@gmail.com>
# 
# Primitive test harness for metazone.
#

clean:
	rm -f metainc.conf metaopts.conf metazone.conf test.mz zone.mastered.*


test.mz: metazone.yaml
	./generate_mz.py --debug > test.mz

test: test.mz
	./bind_mz.py --file=test.mz --host 180.236.121.59 --debug
	sudo named-checkconf -t `pwd` -c example_named.conf

testdbg: test.mz
	pudb3 ./bind_mz.py --file=test.mz --host 180.236.121.59 --debug

testall: test.mz
	./run-all-nsg-test-cases

testnsg: test.mz
	./run-each-nsg-test-cases
