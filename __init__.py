#!/usr/bin/env python
# author: carstein <michal.melewski@gmail.com>
# 10k foot view on binary

from binaryninja import PluginCommand

from modules import function_report

# register plugin
PluginCommand.register_for_function(
  "[Keyhole] Function report",
  "Report about functions in binary",
  function_report.run_plugin)
