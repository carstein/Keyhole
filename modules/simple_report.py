# Author: carstein <michal.melewski@gmail.com>
# Simple report - functions with block size and instructions

import json
import os
import sys
import struct

import binaryninja as bn

class Report:
  def __init__(self):
    pass

  def add_function(self, f):
    pass
    
# Function to be executed when we invoke plugin
def run_plugin(bv, function):
  bn.log_info('[*] Scanning functions...')

  r = Report()

  for function in bv.functions():
    # prefilter
    r.add_function(function)
