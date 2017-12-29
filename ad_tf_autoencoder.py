#!/usr/bin/env python

#
# Anomaly detection using tensorflow and tshark
# Unsupervised learning using autoencoder
#
# Copyright 2017, H21 lab, Martin Kacer
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
from datetime import datetime
import numpy as np

import tensorflow as tf

COLUMNS = []
LABEL_COLUMN = "label"
CATEGORICAL_COLUMNS = []
CONTINUOUS_COLUMNS = []

FLAGS = None


# Parameters
learning_rate = 0.001
training_epochs = 10
batch_size = 256
display_step = 1

# Network Parameters
n_hidden_1 = 15 # 1st layer num features
#n_hidden_2 = 15 # 2nd layer num features
n_input = 1000
data_dir = '.'

weights = {
    'encoder_h1': tf.Variable(tf.random_normal([n_input, n_hidden_1])),
    #'encoder_h2': tf.Variable(tf.random_normal([n_hidden_1, n_hidden_2])),
    'decoder_h1': tf.Variable(tf.random_normal([n_hidden_1, n_input])),
    #'decoder_h2': tf.Variable(tf.random_normal([n_hidden_1, n_input])),
}
biases = {
    'encoder_b1': tf.Variable(tf.random_normal([n_hidden_1])),
    #'encoder_b2': tf.Variable(tf.random_normal([n_hidden_2])),
    'decoder_b1': tf.Variable(tf.random_normal([n_input])),
    #'decoder_b2': tf.Variable(tf.random_normal([n_input])),
}


# Building the encoder
def encoder(x):
    # Encoder Hidden layer with sigmoid activation #1
    layer_1 = tf.nn.tanh(tf.add(tf.matmul(x, weights['encoder_h1']),
                                   biases['encoder_b1']))
    # Decoder Hidden layer with sigmoid activation #2
    #layer_2 = tf.nn.tanh(tf.add(tf.matmul(layer_1, weights['encoder_h2']),
                                   #biases['encoder_b2']))
    return layer_1


# Building the decoder
def decoder(x):
    # Encoder Hidden layer with sigmoid activation #1
    layer_1 = tf.nn.tanh(tf.add(tf.matmul(x, weights['decoder_h1']),
                                   biases['decoder_b1']))
    # Decoder Hidden layer with sigmoid activation #2
    #layer_2 = tf.nn.tanh(tf.add(tf.matmul(layer_1, weights['decoder_h2']),
                                  # biases['decoder_b2']))
    return layer_1


'''def build_estimator(model_dir, model_type):
    """Build an estimator."""
    
    # Wide columns and deep columns.
    wide_columns = []
    
    deep_columns = []
    
    for c in COLUMNS:
        # Sparse base columns.
        print ">>>>>>>>>>>>>>>>>>>"
        print c
        column = tf.contrib.layers.sparse_column_with_hash_bucket(c, hash_bucket_size=10000)
        deep_columns.append(tf.contrib.layers.embedding_column(column, dimension=8))
        #wide_columns.append(column)
    
    if model_type == "wide":
        m = tf.contrib.learn.LinearClassifier(model_dir=model_dir, 
                                              feature_columns=wide_columns)
    elif model_type == "deep":
        m = tf.contrib.learn.DNNClassifier(model_dir=model_dir, 
                                           feature_columns=deep_columns, 
                                           hidden_units=[100, 50])
    else:
        m = tf.contrib.learn.DNNLinearCombinedClassifier(
            model_dir=model_dir,
            linear_feature_columns=wide_columns,
            dnn_feature_columns=deep_columns,
            dnn_hidden_units=[100, 50])
    
    return m
'''

'''
def input_fn(df):
    """Input builder function."""
    # Creates a dictionary mapping from each continuous feature column name (k) to
    # the values of that column stored in a constant Tensor.
    continuous_cols = {k: tf.constant(df[k].values) for k in CONTINUOUS_COLUMNS}
    # Creates a dictionary mapping from each categorical feature column name (k)
    # to the values of that column stored in a tf.SparseTensor.
    categorical_cols = {
        k: tf.SparseTensor(
                indices=[[i, 0] for i in range(df[k].size)],
                values=df[k].values,
                dense_shape=[df[k].size, 1])
        for k in CATEGORICAL_COLUMNS}
    # Merges the two dictionaries into one.
    feature_cols = dict(continuous_cols)
    feature_cols.update(categorical_cols)
 
    label = tf.constant(df[LABEL_COLUMN].values)

    # Returns the feature columns and the label.
    return feature_cols, label
'''

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
            file.write(format(i/2, '06x') + ' ')
        
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
    
    print '==============='
    print COLUMNS
    print CATEGORICAL_COLUMNS
    print CONTINUOUS_COLUMNS
    print '==============='
    
    df = pd.DataFrame()
    
    ln = readJsonEK(df, FLAGS.normal_tshark_ek_x_json, 0)
    #readJsonEK(df, FLAGS.anomaly_tshark_ek_x_json, 1, ln)
    
    df = df.sample(frac=1).reset_index(drop=True)
    
    print(df)

    #####################################
    # train neural network and evaluate #
    #####################################
    model_dir = tempfile.mkdtemp()
    print("model directory = %s" % model_dir)

    print ">>>>>>>>>>>>>>>" + str(COLUMNS)
    #m = build_estimator(model_dir, 'wide_n_deep')
    #
    #m.fit(input_fn=lambda: input_fn(df), steps=200)
    #
    #results = m.evaluate(input_fn=lambda: input_fn(df), steps=1)
    #for key in sorted(results):
    #    print("%s: %s" % (key, results[key]))
    
    # Construct Autoencoder model
    
    #X = tf.placeholder("float", [None, input_fn(df)])
    
    print "!!!!!!!!!!!!!!!!!!!!!"
    print df.iloc[:,2]
    print "!!!!!!!!!!!!!!!!!!!!!"
    train_x = df.iloc[:,2].values
    
    print train_x.shape[1]
    n_input = train_x.shape[1]
    X = tf.placeholder("float", [None, n_input])
    
    encoder_op = encoder(X)
    decoder_op = decoder(encoder_op)
    
    # Prediction
    y_pred = decoder_op
    # Targets (Labels) are the input data.
    y_true = X
    
    # Define batch mse
    batch_mse = tf.reduce_mean(tf.pow(y_true - y_pred, 2), 1)
    
    # Define loss and optimizer, minimize the squared error
    cost = tf.reduce_mean(tf.pow(y_true - y_pred, 2))
    optimizer = tf.train.RMSPropOptimizer(learning_rate).minimize(cost)
    
    # Initializing the variables
    init = tf.global_variables_initializer()
    
    with tf.Session() as sess:
        now = datetime.now()
        sess.run(init)
        total_batch = int(train_x.shape[0]/batch_size)
        # Training cycle
        for epoch in range(training_epochs):
            # Loop over all batches
            for i in range(total_batch):
                batch_idx = np.random.choice(train_x.shape[0], batch_size)
                batch_xs = train_x[batch_idx]
                # Run optimization op (backprop) and cost op (to get loss value)
                _, c = sess.run([optimizer, cost], feed_dict={X: batch_xs})
                
            # Display logs per epoch step
            if epoch % display_step == 0:
                train_batch_mse = sess.run(batch_mse, feed_dict={X: train_x})
                print("Epoch:", '%04d' % (epoch+1),
                      "cost=", "{:.9f}".format(c), 
                      "Train auc=", "{:.6f}".format(auc(train_y, train_batch_mse)), 
                      "Time elapsed=", "{}".format(datetime.now() - now))

    print("Optimization Finished!")
        
        
    '''    
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
        # flush every 100 lines, EK JSON contains also index lines, not packets
        if (i%200) == 0:
            y = m.predict(input_fn=lambda: input_fn(df_predict))
            
            j = 0
            for val in y:
                if (val == 1):
                    print(str(df_predict.iloc[[j]]))
                    # pcap
                    df_to_pcap(j, df_predict, file)
                    
                j = j + 1
            df_predict = pd.DataFrame()
         
    # flush again after
    if len(df_predict) > 0:
        y = m.predict(input_fn=lambda: input_fn(df_predict))
        j = 0
        for val in y:
            if (val == 1):
                print(str(df_predict.iloc[[j]]))
                # pcap
                df_to_pcap(j, df_predict, file)
                
            j = j + 1
            
    # pcap
    f.close()
    to_pcap_file(infile + '.tmp', infile + '.pcap')
    os.remove(infile + '.tmp')
    print("Generated " + infile + ".pcap")
    '''
    


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
cat input.pcap.json | python ad_tf.py -i normal.pcap.json \\
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
""", formatter_class=argparse.RawTextHelpFormatter)
    parser.register("type", "bool", lambda v: v.lower() == "true")
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
    
    print "============"
    #print FLAGS.anomaly_tshark_ek_x_json
    print FLAGS.normal_tshark_ek_x_json
    print FLAGS.fields
    print "============"
    
    main([sys.argv[0]] + unparsed)
