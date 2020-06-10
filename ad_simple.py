#!/usr/bin/env python

# Simple anomaly detection using tshark
# Input is tshark -T ek -x json and output is pcap
#
# Copyright 2020, H21 lab, Martin Kacer
# All the content and resources have been provided in the hope that it will be useful.
# Author do not take responsibility for any misapplication of it.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys
import json
import argparse
import operator
import subprocess
import os
import hashlib

def to_pcap_file(filename, output_pcap_file):
    FNULL = open(os.devnull, 'w')
    subprocess.call(["text2pcap", filename, output_pcap_file], stdout=FNULL, stderr=subprocess.STDOUT)

def hex_to_txt(hexstring, output_file):
    h = hexstring.lower()
    
    file = open(output_file, 'a')
    
    for i in range(0, len(h), 2):
        if(i%32 == 0):
            file.write(format(int(i/2), '06x') + ' ')
        
        file.write(h[i:i+2] + ' ')
        
        if(i%32 == 30):
            file.write('\n')

    file.write('\n')
    file.close()

def json_collector(dict, name):
    r = []
    if hasattr(dict, 'items'):
        for k, v in dict.items():
            if (k in name):
                r.append(v)
            else:
                val = json_collector(v, name)
                if (len(val) > 0):
                    r = r + val

    return r
    

def main(_):
    
    df = []     # Table storing frames, score, hash_key, ...
    d = {}      # Hash dict storing counters
    i = 0

    # Read from stdin line by line
    for line in sys.stdin:
        # trim end of lines
        line = line.rstrip('\n')
        # skip empty lines
        if (line.rstrip() == ""):
            continue
        j = json.loads(line)
        
        # packet found in ek json input
        if ('layers' in j):
            
            # calculate hash-key and store counters in d dict
            fj = json_collector(j, _)
            #print fj
            k = ''
            for f in fj:
                s = str(f)
                m = hashlib.md5()
                m.update(s.encode('utf-8'))
                k = m.hexdigest()
                if k in d:
                    d[k] = d[k] + 1
                else:
                    d[k] = 1
            if(k == ''):
                if k in d:
                    d[k] = d[k] + 1
                else:
                    d[k] = 1
            
            
            # store in df list all the columns
            layers = j['layers']
            
            linux_cooked_header = False
            if ('sll_raw' in layers):
                linux_cooked_header = True
            if ('frame_raw' in layers):
                # columns: frame_id, frame_raw, score, linux_cooked_header_flag, hash_key
                df.append([i, layers['frame_raw'], 0, linux_cooked_header, k])
                i = i + 1
            
    #print d
    
    # Calculate score column in df table
    for index in range(0, len(df)):
        frame = df[index][1]
        df[index][2] = d[df[index][4]]

    #print(df)
    
    # sort the df table by score ascending
    sorted_df = sorted(df, key=operator.itemgetter(2), reverse=False)
    
    #print(sorted_df)
    
    # Generate output pcap
    # open TMP file used by text2pcap
    infile = 'ad_test'
    file = infile + '.tmp'
    f = open(file, 'w')

    # Iterate over packets in JSON
    for index in range(0, len(sorted_df)):
        list = []
        linux_cooked_header = False;

        frame_raw = sorted_df[index][1]

        # for Linux cooked header replace dest MAC and remove two bytes to reconstruct normal frame using text2pcap
        if (sorted_df[index][3]):
            frame_raw = "000000000000" + frame_raw[6*2:] # replce dest MAC
            frame_raw = frame_raw[:12*2] + "" + frame_raw[14*2:] # remove two bytes before Protocol

        hex_to_txt(frame_raw, file)
        
    f.close()
    # Write out pcap
    to_pcap_file(infile + '.tmp', infile + '.pcap')
    print("Generated " + infile + ".pcap")
    os.remove(infile + '.tmp')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""
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

""", formatter_class=argparse.RawTextHelpFormatter)
    parser.register("type", "bool", lambda v: v.lower() == "true")
    FLAGS, unparsed = parser.parse_known_args()
    main(unparsed)
