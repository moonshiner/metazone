#
# LM: 2021-06-26 17:35:47-07:00
# Shawn Instenes <sinstenes@gmail.com>
# 
# Primitive test harness for metazone.
#

clean:
	rm -f metainc.conf metaopts.conf metazone.conf test.mz


test.mz: metazone.yaml
	./generate_mz.py --debug > test.mz

test: test.mz
	./bind_mz.py --file=test.mz --host 180.236.121.59 --debug

testdbg: test.mz
	pudb3 ./bind_mz.py --file=test.mz --host 180.236.121.59 --debug
