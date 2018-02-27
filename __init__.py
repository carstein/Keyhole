#!/usr/bin/env python
# author: carstein <michal.melewski@gmail.com>
# Simple information about functions in program

from binaryninja import PluginCommand

from modules import simple_report

# register plugin
PluginCommand.register_for_function(
  "[Sweeper] Simple report",
  "Seach binary for defined signatures",
  simple_report.run_plugin)
