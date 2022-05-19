#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
# python pickle unserialize

import logging
import pickle

# 序列化
data = {'a': [1, 2.0, 3, 4+6j],
        'b': ('string', u'Unicode string'),
        'c': None}

pickle_data = pickle.dumps(data)
logging.info(pickle_data, type(pickle_data))
print("pickle_data:", pickle_data)
# convert pickle_data to hex
print("pickle_data:", pickle_data.hex())

