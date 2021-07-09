# Running bind locally

    mkdir -p etc/bind
    make test.mz 

    ./bind_mz.py --file=test.mz --host 180.236.121.59 --debug

Then copy files

    cp example_named.conf etc/bind
    cp metaopts.conf etc/bind
    cp metazone.conf etc/bind

then fire up named 

    sudo named -t `pwd` -u ${USER}  -c /etc/bind/example_named.conf 
