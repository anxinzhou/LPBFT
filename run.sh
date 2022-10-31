#!/bin/bash

trap "kill 0" SIGINT

for i in {0..3}
do
  port=5000$i
  if [ $i != 3 ]
  then
  ./pserver_linux --port=$port --id=$i --config-file="config/remoteConfig.json" &
  else
    ./pserver_linux --port=$port --id=$i --config-file="config/remoteConfig.json"
    fi
done



#./pserver --port=50001

#./proserver --port=50001