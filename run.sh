trap "kill 0" SIGINT
for i in {0..3}
do
  port=5000$i
  if [ $i != 3 ]
  then
  ./pserver --port=$port --id=$i &
  else
    ./pserver --port=$port --id=$i
    fi
done



#./pserver --port=50001

#./proserver --port=50001