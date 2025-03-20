    python3 -m venv venv
    . ./venv/bin/activate
    pip3 install .
    cd src/euwallet_cli
    ./client.py <client.conf> (e.g client-test.conf)

TODO: save function division
TODO: add  issuer selection  from the list 

For different flows:

        cd src/euwallet_cli

        ./typer_wrapper.py --help

        ./typer_wrapper.py  ehic --issuer-to-use https://satosa-test-1.sunet.se  --config-path client-test.conf

        ./typer_wrapper.py  pda1 --issuer-to-use https://satosa-test-1.sunet.se  --config-path client-test.conf

        ./typer_wrapper.py  pid --issuer-to-use https://satosa-test-1.sunet.se  --config-path client-test.conf



Install in development mode
        
        pip install -e '.[dev]' 
 


