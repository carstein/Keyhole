# Author: carstein <michal.melewski@gmail.com>
# Function report - functions with block size and instructions

import os
import binaryninja as bn

from fingerprint import FingerprintReport


# It does not end with /
PLUGINDIR_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

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
    #                   'calls': [<call_instr>], // how many other functions are being called
    #                   'xrefs': [<ref>], // how many functions call this function
    #                   'fingerprint: <image>,' //Image of binary fingerprint
    #                   'size': 'small'}
    }

  def __get_function_row(self, name, data):
    template = self.templates['function_row']
    return template.format(start = data['start'],
                           name = name,
                           instructions = data['instructions'],
                           blocks = data['blocks'],
                           calls = len(data['calls']),
                           xrefs = len(data['xrefs']),
                           size = data['size'],
                           w = self.bv.arch.address_size*2)

  def __extract_call_target(self, instr):
    if instr.dest.operation == bn.LowLevelILOperation.LLIL_CONST_PTR:
      addr = instr.dest.constant
      return addr, self.bv.get_function_at(addr).name
    else:
      return 0, "[{}]".format(instr.dest)

  def __get_function_pane(self, name, data):
    template = self.templates['function_pane']
    xref_rows = ''

    for xref in data['xrefs']:
      xref_rows += self.templates['function_xref_row'].format(addr = xref.address,
                                                              name = xref.function.name,
                                                              w = self.bv.arch.address_size*2)
    calls_rows = ''
    for call in data['calls']:
      call_addr, call_name = self.__extract_call_target(call)
      calls_rows += self.templates['function_call_row'].format(addr = call_addr,
                                                               name = call_name,
                                                               w = self.bv.arch.address_size*2)

    fingerprint_image = self.templates['fingerprint'].format(img = data['fingerprint'])
    return template.format(id = name,
                           calls_rows = calls_rows,
                           xref_rows = xref_rows,
                           img = fingerprint_image)

  def add_function(self, f):
    b, i  = 0, 0
    c = []

    # Basic data
    for block in f.low_level_il:
      b += 1
      for inst in block:
        i += 1
        if inst.operation == bn.LowLevelILOperation.LLIL_CALL:
          c.append(inst)

    # Binary fingerprint
    fingerprint = FingerprintReport()

    for inst in f.instructions:
      fingerprint.add(inst[0][0].text)

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
                                  'xrefs': self.bv.get_code_refs(f.start),
                                  'size': size,
                                  'fingerprint': fingerprint.create_image()
                                  }

  def load_template(self, name, template):
    template_path = PLUGINDIR_PATH + "/data/" + template

    with open(template_path) as fh:
      self.templates[name] = fh.read()

  def generate_html(self):
    html = self.templates['main']
    f_table = ''
    panes = ''

    for name, data in sorted(self.function_data.iteritems(), reverse=True, key=lambda x: x[1]['instructions']):
      f_table += self.__get_function_row(name, data)
      panes   += self.__get_function_pane(name, data)

    return html.format(f_number = len(self.function_data.keys()),
                       f_table = f_table,
                       f_panes = panes)

def run_plugin(bv, function):
  # Supported platform check
  if bv.platform.name not in supported_arch:
    log_error('[x] Right now this plugin supports only the following platforms: ' + str(supported_arch))
    return -1

  r = Report(bv)
  r.load_template('main','functions_report.html')
  r.load_template('function_row', 'function_table_row.tpl')
  r.load_template('function_pane', 'function_pane.tpl')
  r.load_template('function_call_row', 'function_call_row.tpl')
  r.load_template('function_xref_row', 'function_xref_row.tpl')
  r.load_template('fingerprint', 'fingerprint_image.tpl')

  bn.log_info('[*] Scanning functions...')
  for function in bv.functions:
    if function.symbol.type != bn.SymbolType.ImportedFunctionSymbol:
      r.add_function(function)

  save_filename = bn.interaction.get_save_filename_input("Save report to ...")

  if save_filename:
    with open(save_filename, "w+") as fh:
      fh.write(r.generate_html())
