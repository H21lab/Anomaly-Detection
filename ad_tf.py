#!/usr/bin/env python

#
# Anomaly detection using tensorflow and tshark
# Supervised learning using neural network classifier
#
# Copyright 2020, H21 lab, Martin Kacer
# All the content and resources have been provided in the hope that it will be useful.
# Author do not take responsibility for any misapplication of it.
#
# Based on tensorflow classifier example wide_n_deep_tutorial.py
# Copyright 2017, The TensorFlow Authors.
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
import tempfile
import pandas as pd
import operator
import subprocess
import os
import hashlib
import tensorflow as tf
tf.estimator.Estimator._validate_features_in_predict_input = lambda *args: None

tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.DEBUG)

COLUMNS = []
LABEL_COLUMN = "label"
CATEGORICAL_COLUMNS = []
CONTINUOUS_COLUMNS = []

FLAGS = None

def build_model_columns():
    """Builds a set of wide and deep feature columns."""

    # Wide columns and deep columns.
    wide_columns = []

    deep_columns = []

    for c in COLUMNS:
        # Sparse base columns.
        print(">>>>>>>>>>>>>>>>>>>")
        print(c)
        column = tf.feature_column.categorical_column_with_hash_bucket(c, hash_bucket_size=10000)
        deep_columns.append(tf.feature_column.embedding_column(column, dimension=8))
        #wide_columns.append(column)

    return wide_columns, deep_columns

def build_estimator(model_dir, model_type):
    """Build an estimator appropriate for the given model type."""
    wide_columns, deep_columns = build_model_columns()
    hidden_units = [100, 75, 50, 25]

    run_config = tf.estimator.RunConfig().replace(keep_checkpoint_max = 5,
                    log_step_count_steps=20, save_checkpoints_steps=200)

    if model_type == 'wide':
        return tf.estimator.LinearClassifier(
            model_dir=model_dir,
            feature_columns=wide_columns,
            config=run_config)
    elif model_type == 'deep':
        return tf.estimator.DNNClassifier(
            model_dir=model_dir,
            feature_columns=deep_columns,
            hidden_units=hidden_units,
            config=run_config)
    else:
        return tf.estimator.DNNLinearCombinedClassifier(
            model_dir=model_dir,
            linear_feature_columns=wide_columns,
            dnn_feature_columns=deep_columns,
            dnn_hidden_units=hidden_units,
            config=run_config)

def input_fn(df, num_epochs, shuffle, batch_size):
    """Input builder function."""
    dataset = tf.data.Dataset.from_tensor_slices((dict(df[COLUMNS]), df['label']))

    if shuffle:
        dataset = dataset.shuffle(1000)

    dataset = dataset.repeat(num_epochs)
    dataset = dataset.batch(batch_size)
    return dataset

def df_to_pcap(j, df_predict, file):
    linux_cooked_header = df_predict.at[j, 'linux_cooked_header'];
    frame_raw = df_predict.at[j, 'frame_raw']
    # for Linux cooked header replace dest MAC and remove two bytes to reconstruct normal frame using text2pcap
    if (linux_cooked_header):
        frame_raw = "000000000000" + frame_raw[6*2:] # replce dest MAC
        frame_raw = frame_raw[:12*2] + "" + frame_raw[14*2:] # remove two bytes before Protocol
    hex_to_txt(frame_raw, file)

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
    
def readJsonEKLine(df, line, label):
    # trim end of lines
    line = line.rstrip('\n')
    # skip empty lines
    if (line.rstrip() == ""):
        return

    j = json.loads(line)
                
    # frames
    if ('layers' in j):
        layers = j['layers']

        linux_cooked_header = False
        if ('sll_raw' in layers):
            linux_cooked_header = True
        if ('frame_raw' in layers):

            i = len(df)

            df.loc[i, 'frame_raw'] = layers['frame_raw']
            df.loc[i, 'linux_cooked_header'] = linux_cooked_header
            
            for c in COLUMNS:
                v = json_collector(j, [c])
                if (len(v) > 0):
                    v = v[0]
                else:
                    v = ''
                df.loc[i, c] = v

            df.loc[i, 'label'] = label

def readJsonEK(df, filename, label, limit = 0):
    i = 0
    while i <= limit:
        with open(filename) as f:
            for line in f:
                if (limit != 0 and i > limit):
                    return i
                readJsonEKLine(df, line, label)
                i = i + 1
    return i

def main(_):
    
    global COLUMNS
    global CATEGORICAL_COLUMNS
    COLUMNS = FLAGS.fields
    CATEGORICAL_COLUMNS = COLUMNS
    
    print('===============')
    print(COLUMNS)
    print(CATEGORICAL_COLUMNS)
    print(CONTINUOUS_COLUMNS)
    print('===============')

    df = pd.DataFrame()

    ln = readJsonEK(df, FLAGS.normal_tshark_ek_x_json, 0)
    readJsonEK(df, FLAGS.anomaly_tshark_ek_x_json, 1, ln)

    df = df.sample(frac=1).reset_index(drop=True)

    print(df)

    #####################################
    # train neural network and evaluate #
    #####################################
    model_dir = tempfile.mkdtemp()
    print("model directory = %s" % model_dir)

    print(">>>>>>>>>>>>>>>" + str(COLUMNS))
    model = build_estimator(model_dir, 'wide_n_deep')

    # Train and evaluate the model every `FLAGS.epochs_per_eval` epochs.
    train_epochs = 100
    epochs_per_eval = 20
    train_steps = 400
    for n in range(train_epochs // epochs_per_eval):
        model.train(input_fn=lambda: input_fn(df, train_epochs, True, train_steps))

        results = model.evaluate(input_fn=lambda: input_fn(df, train_epochs, True, train_steps))

    # Display evaluation metrics
    print('Results at epoch', (n + 1) * epochs_per_eval)
    print('-' * 60)

    for key in sorted(results):
        print('%s: %s' % (key, results[key]))

    #####################################
    # read from stdin and predict       #
    #####################################
    # Generate pcap
    # open TMP file used by text2pcap

    infile = 'ad_test'
    file = infile + '.tmp'
    f = open(file, 'w')

    df_predict = pd.DataFrame()

    i = 0;
    for line in sys.stdin:
        readJsonEKLine(df_predict, line, 0)  

        i = i + 1

        #print(df_predict)

        # flush every 100 lines, EK JSON contains also index lines, not packets
        if (i%200) == 0:
            y = model.predict(input_fn=lambda: input_fn(df_predict, 1, False, 100))
            #print("=======================")
            #print(y)
            #print("=======================")

            j = 0
            for val in y:
                #print("****")
                #print(val)
                #print("****")
                if (val == 1):
                    print(str(df_predict.iloc[[j]]))
                    # pcap
                    df_to_pcap(j, df_predict, file)

                j = j + 1

            # check predicted labels
            if len(df_predict) > 0:
                y = model.predict(input_fn=lambda: input_fn(df_predict, 1, False, 100))
                j = 0
                for val in y:
                    label = val['class_ids'][0]
                    if (label == 1):
                        print("index = " + str(j))
                        print("label = " + str(label))
                        print("Probability = " + str(val['probabilities'][label]))
                        print(str(df_predict.iloc[[j]]))
                        # pcap
                        df_to_pcap(j, df_predict, file)

                    j = j + 1

            # flush
            df_predict = pd.DataFrame()

    # pcap
    f.close()
    to_pcap_file(infile + '.tmp', infile + '.pcap')
    os.remove(infile + '.tmp')
    print("Generated " + infile + ".pcap")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""
Script to help to detect anomalies in pcap file.
Using tensorflow neural network classifier and tshark -T ek -x input.

Input is tshark ek json generate by:
./tshark -T ek -x -r trace.pcap > input.json

Run script:
cat input.pcap.json | python ad_tf.py -i normal.pcap.json \\
 -a anomaly.pcap.json -f field_1 field_2 .... field_n

For fields the name of the fields from json ek should be used, e.g.:
tshark -T ek -x -r ./res/input.pcap.gz | python ad_tf.py \\
   -i res/normal.json -a res/anomaly.json -f tcp_tcp_flags_raw \\
   tcp_tcp_dstport_raw

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
""", formatter_class=argparse.RawTextHelpFormatter)
    parser.register("type", "bool", lambda v: v.lower() == "true")
    parser.add_argument(
        "-a",
        "--anomaly_tshark_ek_x_json",
        type=str,
        default="",
        help="Anomaly traffic. Json created by tshark -T ek -x from pcap.\nShall contain only frames considered as anomalies.",
        required=True
    )
    parser.add_argument(
        "-i",
        "--normal_tshark_ek_x_json",
        type=str,
        default="",
        help="Regular traffic. Json created by tshark -T ek -x from pcap.\nShall contain only frames considered as normal.",
        required=True
    )
    parser.add_argument(
        "-f",
        "--fields",
        nargs='+',
        help='field_1 field_2 .... field_n (e.g. ip_ip_src ip_ip_dst)',
        required=True
    )

    FLAGS, unparsed = parser.parse_known_args()

    print("============")
    print(FLAGS.anomaly_tshark_ek_x_json)
    print(FLAGS.normal_tshark_ek_x_json)
    print(FLAGS.fields)
    print("============")

    main([sys.argv[0]] + unparsed)
