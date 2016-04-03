#! /usr/bin/env python

# Standard libraries
import argparse
import os
import urllib2
import sys

# 3rd party libraries
import boto3
import boto3.session
import netaddr

# project libraries
import lib.core
import lib.analyze

def parse_args(str_to_parse=None):
  """
  Parse the command line args
  """
  cmd = ""
  if len(sys.argv) > 1:
    cmd = sys.argv[1]

  return cmd

class Script(lib.core.ScriptContext):
  def __init__(self, command_to_run):
    self.command_to_run = command_to_run
    self.available_commands = {
        'analyze': 
          { 
            'help': 'Analyze a set of Amazon Inspector findings',
            'cmd': lib.analyze.run_script,
          },
      }

    if not self.command_to_run in self.available_commands.keys():
      self.print_help()
    else:
      # run a specific command
      self.available_commands[self.command_to_run]['cmd'](sys.argv[1:])

  def print_help(self):
    """
    Print the command line syntax available to the user
    """
    self.update_user("usage: ds-analyze-findings [COMMAND]\n   For more help on a specific command, type ds-analyze-findings [COMMAND] --help\n\n   Available commands:\n")
    for cmd, data in self.available_commands.items():
      self.update_user("   {}\n      > {}".format(cmd, data['help']))
    self.update_user("")

def main():
  """
  Run the script from the command line
  """
  context = Script(parse_args())

if __name__ == '__main__': main()