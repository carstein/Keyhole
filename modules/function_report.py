# Author: carstein <michal.melewski@gmail.com>
# Function report - functions with block size and instructions

import os
import binaryninja as bn


supported_arch = [
  'linux-x86',
  'linux-x86_64'
]

class Report:
  def __init__(self, bv):
    self.bv = bv
    self.templates = {}
    self.function_data = {
    # 'function_name': {'start':0x08040000,
    #                   'blocks':10,
    #                   'instructions': 50,
    #                   'calls': 5, // how many other functions are being called
    #                   'xrefs': 2, // how many functions call this function
    #                   'size': 'small'}
    }

  def __get_function_row(self, name, data):
    template = self.templates['function_row']
    return template.format(start = data['start'],
                           name = name,
                           instructions = data['instructions'],
                           blocks = data['blocks'],
                           calls = data['calls'],
                           xrefs = data['xrefs'],
                           size = data['size'],
                           w = self.bv.arch.address_size*2)

  def add_function(self, f):
    b, i, c = 0, 0, 0
    x = len(self.bv.get_code_refs(f.start))

    for block in f.low_level_il:
      b += 1
      for inst in block:
        i += 1
        if inst.operation == bn.LowLevelILOperation.LLIL_CALL:
          c += 1

    # naivly determine function size
    if b == 1 or i < 10:
      size = 'small'
    elif i < 100:
      size = 'medium'
    else:
      size = 'large'

    self.function_data[f.name] = {'start': f.start,
                                  'blocks': b,
                                  'instructions': i,
                                  'calls': c,
                                  'xrefs': x,
                                  'size': size
                                  }

  def generate_html(self):
    html = self.templates['main']
    table = ''

    for name, data in sorted(self.function_data.iteritems(), reverse=True, key=lambda x: x[1]['instructions']):
      table = table + self.__get_function_row(name, data)

    return html.format(f_number = len(self.function_data.keys()),
                       f_table = table)

  def load_template(self, name, template):
    with open(bn.user_plugin_path + '/keyhole/data/' + template) as fh:
      self.templates[name] = fh.read()

def run_plugin(bv, function):
  # Supported platform check
  if bv.platform.name not in supported_arch:
    log_error('[x] Right now this plugin supports only the following platforms: ' + str(supported_arch))
    return -1

  r = Report(bv)
  r.load_template('main','functions_report.html')
  r.load_template('function_row', 'function_table_row.tpl')

  bn.log_info('[*] Scanning functions...')
  for function in bv.functions:
    if function.symbol.type != bn.SymbolType.ImportedFunctionSymbol:
      r.add_function(function)

  save_filename = bn.interaction.get_save_filename_input("Save report to ...")

  if save_filename:
    with open(save_filename, "w+") as fh:
      fh.write(r.generate_html())

  #bn.interaction.show_html_report('Functions report', r.generate_html(), 'Not available')
