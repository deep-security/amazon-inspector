# standard libraries
from __future__ import division
import argparse
import re
import os
import urllib2

# 3rd party libraries
import boto3
import boto3.session
import deepsecurity

# project libraries
import core
import utilities

def run_script(args):
  # configure the command line args
  parser = core.get_arg_parser(prog='ds-analyze-findings coverage', add_help=True)
  parser.add_argument('--print-cve-only', action='store_true', dest='print_cve_only', required=False, help='Print only the CVEs covered by both Amazon Inspector and Deep Security. Useful to piping to other commands when not used with the --verbose switch')

  script = Script(args[1:], parser)

  script.connect()
  in_inspector = script.get_cves_from_inspector()
  in_ds = script.get_cves_in_ds()
  coverage = script.compare_cves(in_inspector, in_ds)
  if script.args.print_cve_only:
    coverage.sort()
    print "\n".join(coverage)
  else:
    script.print_coverage(coverage, in_inspector, in_ds)

  script.clean_up()

  return coverage

class Script(core.ScriptContext):
  def __init__(self, args, parser):
    core.ScriptContext.__init__(self, args, parser)
    self.dsm = None
    self.inspector = None
    self.aws_credentials = self._get_aws_credentials()

  def connect(self):
    """
    Connect to Deep Security and Amazon Inspector
    """
    self.dsm = self._connect_to_deep_security()

  def get_cves_in_ds(self):
    """
    Get a list of available CVE protection in Deep Security
    """
    cves = []

    if self.dsm:
      self.dsm.rules.get()
      for rule_id, rule in self.dsm.rules['intrusion_prevention'].items():
        if rule.cve_numbers:
          for cve in rule.cve_numbers:
            cves.append(cve)

    return cves

  def get_cves_from_inspector(self):
    """
    Get all of the findings and their associated data from Amazon Inspector
    """
    results = []
    
    cve_url = 'https://s3-us-west-2.amazonaws.com/rules-engine/CVEList.txt'

    txt = None
    try:
      uh = urllib2.urlopen(cve_url)
      if uh: txt = uh.read()
    except Exception, err:
      self._log("Could not download the list of currently support CVEs by Amazon Inspector")

    if txt:
      for line in txt.split('\n'):
        results.append(line.strip())

    return results

  def compare_cves(self, in_inspector, in_ds):
    """
    Compare the coverage in CVEs between Amazon Inspector and Deep Security
    """
    results = []

    for cve in in_ds:
      if cve in in_inspector: results.append(cve)

    return results

  def print_coverage(self, coverage, in_inspector, in_ds):
    """
    Print the coverage of CVEs between Amazon Inspector and Deep Security
    """
    print "\n***********************************************************************"
    print "* CVE Coverage"
    print "***********************************************************************"

    print "Amazon Inspector's rule set currently looks for {} CVEs".format(len(in_inspector))
    print "Deep Security's intrusion prevention rule set currently looks for {} CVEs".format(len(in_ds))
    print ""
    coverage_percentage = (len(coverage)/len(in_inspector)) * 100
    print "{} ({:.2f}%) of the CVEs that Amazon Inspector looks for can be remotely mitigated by Deep Security".format(len(coverage), coverage_percentage)
    print ""
