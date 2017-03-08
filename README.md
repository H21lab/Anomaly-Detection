# Anomaly Detection using tensorflow and tshark
```shell-session
Script to help to detect anomalies in pcap file.
Using tensorflow neural network classifier and tshark -T ek -x input.

Input is tshark ek json generate by:
./tshark -T ek -x -r trace.pcap > input.json

Run script:
cat input.pcap.json | python ad_tf.py -i normal.pcap.json \
 -a anomaly.pcap.json -f field_1 field_2 .... field_n

For fields the name of the fields from json ek should be used, e.g.:
cat input.pcap.json | python ad_tf.py -i normal.pcap.json \
 -a anomaly.pcap.json -f ip_ip_src ip_ip_dst

Output pcap
ad_test.pcap

The script  uses the tshark ek  jsons including the raw  hex data generated
from pcaps by command as described above. The fields arguments are used for
anomaly detection. The fields are used as columns, hashed and used as input
to tensorflow neural classifier network.

The neural classifier network is  first trained with normal.pcap.json input
with label 0 and with anomaly.pcap.json  input with label 1. After training
then  from stdin  is read  the  input.pcap.json and  evaluated. The  neural
network predicts the label.

The output  pcap contains then  the frames  predicted by neural  network as
anomalies with label 1.
```

# Simple Anomaly Detection using tshark
```shell-session
Simple script to help to detect anomalies in pcap file.

Input is tshark ek json generate by:
./tshark -T ek -x -r trace.pcap > input.json

Run script:
cat input.json | python ad_simple.py field_1 field_2 .... field_n

For fields the name of the fields from json ek should be used, e.g.:
cat input.json | python ad_simple.py ip_ip_src ip_ip_dst

Output pcap
ad_test.pcap

The script read the tshark ek json including the raw hex data. The input is
generated from pcap using tshark. The  fields arguments are used for simple
anomaly detection. The  behavior is similar like SQL GROUP  BY command. The
fields  are  hashed  together  and  the output  pcap  contains  the  frames
beginning with most unique combination of selected fields and descending to
most frequent frames containing the selected fields.

The following example
    cat input.json | python ad_simple.py ip_ip_src ip_ip_dst
will  generate pcap starting with less  frequent combinations of source and
dest IP pairs and descending to frames with common
combinations.
```

Limitations

Program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.

## Attribution

This code was created by Martin Kacer, H21 lab, Copyright 2017.
https://sites.google.com/site/h21lab

