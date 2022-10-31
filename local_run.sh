#!/bin/bash

trap "kill 0" SIGINT

#inet_ip=$(ifconfig | grep 'inet' | head -n 1 | awk '{print $2}')
inet_ip="localhost"
configFilePath="config/localConfig.json"

for i in {0..3}
do
  port=5000$i
  addr="${inet_ip}:${port}"
  id=$(cat $configFilePath | python3 -c "import sys, json; print(json.load(sys.stdin)['address'].index(\"${addr}\"))")
  if [ $i != 3 ]
  then
  ./pserver_linux --port=$port --id=$id --config-file=$configFilePath &
  else
    ./pserver_linux --port=$port --id=$id --config-file=$configFilePath
    fi
done



#./pserver --port=50001

#./proserver --port=50001