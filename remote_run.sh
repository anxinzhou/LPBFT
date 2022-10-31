#!/bin/bash

trap "kill 0" SIGINT

inet_ip=$(ifconfig | grep 'inet' | head -n 1 | awk '{print $2}')
#inet_ip="localhost"
configFilePath="config/remoteConfig.json"
port=50000
addr="${inet_ip}:${port}"
id=$(cat $configFilePath | python3 -c "import sys, json; print(json.load(sys.stdin)['address'].index(\"${addr}\"))")
./pserver_linux --port=$port --id=$id --config-file=$configFilePath



#./pserver --port=50001

#./proserver --port=50001