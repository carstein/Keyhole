# Author: carstein <michal.melewski@gmail.com>
# Simple report - functions with block size and instructions

import os
import binaryninja as bn

from string import Template

supported_arch = [
  'linux-x86',
  'linux-x86_64'
]

class Report:
  def __init__(self, bv):
    self.function_data = {
    # 'function_name': {'start':0x08040000,
    #                   'blocks':10,
    #                   'instructions': 50,
    #                   'calls': 5} // how many other functions are being called
    }

    self.templates = {}
    self.bv = bv

  def __get_function_row(self, name, data):
    template = '''
    <tr>
    <td class='f_name'>0x{start:x}: {name}</td>
    <td>{instructions}</td>
    <td>{blocks}</td>
    <td>{calls}</td>
    <td>{xrefs}</td>
    </tr>
    '''
    print data['calls']
    return template.format(start = data['start'],
                           name = name,
                           blocks = data['blocks'],
                           instructions = data['instructions'],
                           calls = data['calls'],
                           xrefs = data['xrefs']
                           )


  def add_function(self, f):
    bn.log_info('[+] Adding function')
    b, i, c = 0, 0, 0
    x = len(self.bv.get_code_refs(f.start))

    for block in f.low_level_il:
      b += 1
      for inst in block:
        i += 1
        if inst.operation == bn.LowLevelILOperation.LLIL_CALL:
          c += 1

    self.function_data[f.name] = {'start': f.start,
                                  'blocks': b,
                                  'instructions': i,
                                  'calls': c,
                                  'xrefs': x
                                  }

  def generate_html(self):
    html = Template(self.templates['simple_report.html'])
    table = ''

    for name, data in sorted(self.function_data.iteritems(), reverse=True, key=lambda x: x[1]['instructions']):
      table = table + self.__get_function_row(name, data)

    return html.substitute(f_number = len(self.function_data.keys()),
                           f_table = table)

  def load_template(self, template):
    with open(bn.user_plugin_path + '/sweeper/data/' + template) as fh:
      self.templates[template] = fh.read()

def run_plugin(bv, function):
  # Supported platform check
  if bv.platform.name not in supported_arch:
    log_error('[x] Right now this plugin supports only the following platforms: ' + str(supported_arch))
    return -1

  r = Report(bv)
  r.load_template('simple_report.html')

  bn.log_info('[*] Scanning functions...')
  for function in bv.functions:
    if function.symbol.type != bn.SymbolType.ImportedFunctionSymbol:
      r.add_function(function)

  bn.interaction.show_html_report('Functions report', r.generate_html(), 'Not available')
