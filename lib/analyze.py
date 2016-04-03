# standard libraries
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
  parser = core.get_arg_parser(prog='ds-analyze-findings analyze', add_help=True)
  parser.add_argument('-l', '--list', action='store_true', required=False, help='List the available Amazon Inspector findings')
  parser.add_argument('-m', '--mitigate', action='store_true', required=False, help='Mitigate Amazon Inspector findings when possible using Deep Security')
  #parser.add_argument('-i', '--id', action='store', dest="ip_list", required=False, help='Specify an IP List by ID within Deep Security as the source for the AWS WAF IP Set')
  
  script = Script(args[1:], parser)

  details = None
  if script.args.list:
    # List the available findings in Amazon Inspector
    script.connect()
    details = script.get_findings()
    if details:
      results = script.reconcile_findings(details)

      print results

    #script._log("***********************************************************************", priority=True)
    #script._log("* DRY RUN ENABLED. NO CHANGES WILL BE MADE", priority=True)
    #script._log("***********************************************************************", priority=True)

  script.clean_up()

  return details

class Script(core.ScriptContext):
  def __init__(self, args, parser):
    core.ScriptContext.__init__(self, args, parser)
    #super(Script, self).__init__(args, parser)
    self.aws_credentials = None
    self.dsm = None
    self.inspector = None

    self.aws_credentials = self._get_aws_credentials()


  def connect(self):
    """
    Connect to Deep Security and Amazon Inspector
    """
    self.dsm = self._connect_to_deep_security()
    self.inspector = self._connect_to_amazon_inspector()

  def get_cves_in_ds(self):
    """
    Get a list of available CVE protection in Deep Security
    """
    cves = {}

    if self.dsm:
      self.dsm.rules.get()
      for rule_id, rule in self.dsm.rules['intrusion_prevention'].items():
        if rule.cve_numbers:
          for cve in rule.cve_numbers:
            if not cves.has_key(cve): cves[cve] = []
            cves[cve].append(rule_id)

    return cves

  def get_findings(self):
    """
    Get all of the findings and their associated data from Amazon Inspector
    """
    results = {
      'targets': utilities.CoreDict(),
      'templates': utilities.CoreDict(),
      'runs': utilities.CoreDict(),
      'findings': utilities.CoreDict(),
      }

    self._log("Starting to walk through the various Inspector primitives")

    # Starting from scratch, you have to query Inspector API objects in this order;
    # 1. assessment targets
    # 2. assessment templates
    # 3. assessment runs
    # 4. findings

    # get all of the available ARNs
    arns = {
      'targets': [],
      'templates': [],
      'runs': [],
      'findings': [],
      }
    try:
      arns['targets'] = self.inspector.list_assessment_targets()
      arns['templates'] = self.inspector.list_assessment_templates(assessmentTargetArns=arns['targets']['assessmentTargetArns'])
      arns['runs'] = self.inspector.list_assessment_runs(assessmentTemplateArns=arns['templates']['assessmentTemplateArns'])
      arns['findings'] = self.inspector.list_findings(assessmentRunArns=arns['runs']['assessmentRunArns'])
    except Exception, arn_err:
      self._log("Unable to query Amazon Inspector for findings", err=arn_err)

    # get any additional details
    details = {
      'targets': {},
      'templates': {},
      'runs': {},
      'findings': {},
      }
    try:
      details['targets'] = self.inspector.describe_assessment_targets(assessmentTargetArns=arns['targets']['assessmentTargetArns'])
      details['templates'] = self.inspector.describe_assessment_templates(assessmentTemplateArns=arns['templates']['assessmentTemplateArns'])
      details['runs'] = self.inspector.describe_assessment_runs(assessmentRunArns=arns['runs']['assessmentRunArns'])
      details['findings'] = self.inspector.describe_findings(findingArns=arns['findings']['findingArns'])
    except Exception, arn_err:
      self._log("Unable to query Amazon Inspector for details about findings", err=arn_err)

    # setup the data structure to capture additional details and make reporting easier
    for k, v in arns.items():
      arns_key = 'assessment{}Arns'.format(k.rstrip('s').capitalize())
      if k == 'findings': arns_key = 'findingArns'
      if v.has_key(arns_key):
        for arn in v[arns_key]:
          results[k][arn] = None

    # make sure we have the data required to proceed
    enough_data_to_proceed = True
    for k, v in arns.items():
      if len(v) == 0:
        self._log("No ARNs available for {}. Please start an assessment run in Amazon Inspector before running this tool".format(k), priority=True)
        enough_data_to_proceed = False

    for k, v in details.items():
      if len(v) == 0:
        self._log("No data available for any assessment {}. At least one assessment run must be finished for this tool to produce any results".format(k), priority=True)
        enough_data_to_proceed = False

    if not enough_data_to_proceed: 
      # exit now
      return None 

    # map out the data structure
    for k, v in details.items():
      details_key = 'assessment{}'.format(k.capitalize())
      if k == 'findings': details_key = k
      for details in v[details_key]:
        if results[k].has_key(details['arn']):
          results[k][details['arn']] = details
          arn_pattern = r'(?P<target>arn:aws:inspector:.+)(?P<template>template.+)?(?P<run>run.+)?(?P<finding>finding.+)?'
          m = re.search(arn_pattern, details['arn'])
          if m:
            results[k][details['arn']]['target'] = "{}".format(m.group('target'))
          if k in ['templates', 'runs', 'findings']:
            results[k][details['arn']]['template'] = "{}{}".format(m.group('target'), m.group('template'))
          if k in ['runs', 'findings']:
            results[k][details['arn']]['run'] = "{}{}".format(m.group('target'), m.group('template'), m.group('run'))

    return results

  def reconcile_findings(self, details):
    """
    Reconcile the findings from Amazon Inspector with Deep Security
    """
    results = {}

    self._log("Getting the latest data from Deep Security")
    self.dsm.computers.get()
    cves_in_ds = self.get_cves_in_ds()
    cves_in_inspector = {}

    # line up all of the runs and findings by instance
    for template_arn, template in details['templates'].items():
      runs = details['runs'].find(template=template_arn)
      # get the details for this run by instance
      for run_arn in runs:
        self._log("Getting the details of run {}".format(run_arn))
        instances = {}
        for finding_arn in details['findings'].find(run=run_arn):
          finding = details['findings'][finding_arn]
          instance_id = None
          if finding.has_key('assetAttributes') and finding['assetAttributes'].has_key('agentId'):
            instance_id = finding['assetAttributes']['agentId']
            self._log("Instance {} has at least one findng".format(instance_id))
          else:
            if 'did not find any potential security issues' in finding['description']:
              # no issues found
              self._log("Positive confirmation of no issues found")
            else:
              # issues or error thrown
              pass # @TODO handle this edge case better
          
          if instance_id:
            if not instances.has_key(instance_id):
              # first time we've seen this instance
              instances[instance_id] = utilities.CoreDict()
              instances[instance_id]['findings'] = []
              is_in_deepsecurity = self.dsm.computers.find(cloud_instance_id=instance_id)
              if len(is_in_deepsecurity) > 0: 
                instances[instance_id]['ds_obj'] = self.dsm.computers[is_in_deepsecurity[0]]
              else:
                # deep security doesn't know about this instance
                instances[instance_id]['ds_obj'] = None

            instances[instance_id]['findings'].append(finding)

          # record any CVEs in the finding
          if finding.has_key('attributes'):
            for kp in finding['attributes']:
              if kp['key'] == 'CVE_ID':
                if not finding.has_key('cves'): instances[instance_id]['cves'] = []
                instances[instance_id]['cves'].append(kp['value'])
                cves_in_inspector[kp['value']] = finding

        # for each instance, let's figure out the mitigation for each CVE reported
        for instance_id, instance_details in instances.items():
          results[instance_id] = {
            'cves': {},
            'is_active_in_deep_security': True if instance_details['ds_obj'] else False,
            'has_intrusion_prevention_enabled_in_deep_security': True if instance_details['ds_obj'] and instance_details['ds_obj']['overall_intrusion_prevention_status'].lower() != 'off' else False,
            'requires_mitigation': False,
            }
          if len(instance_details['cves']) > 0: # this instance is impacts by one or more CVEs
            # can Deep Security protect against this CVE?
            print 'Instance {} is impacted by {} CVEs'.format(instance_id, len(instance_details['cves']))
            for cve_number in instance_details['cves']:
              results[instance_id]['cves'][cve_number] = {
                'immediate_mitigation_rule_id': cves_in_ds[cve_number] if cves_in_ds.has_key(cve_number) else None,
                'immediate_mitigation': self.dsm.rules['intrusion_prevention'][cves_in_ds[cve_number]]['name'] if cves_in_ds.has_key(cve_number) else None,
                'mitigation': cves_in_inspector[cve_number]['description'] if cves_in_inspector.has_key(cve_number) else 'http://cve.mitre.org/cgi-bin/cvename.cgi?name={}'.format(cve_number),
              }

          if len(results[instance_id]['cves']) > 0: results[instance_id]['requires_mitigation'] = True

    return results

  def print_findings(self, details, dsm):
    """
    """
    dsm.computers.get()

    for template_arn, template in details['templates'].items():
      print template
      runs = details['runs'].find(template=template_arn)
      # get the details for this run by instance
      for run_arn in runs:
        instances = {}
        for finding_arn in details['findings'].find(run=run_arn):
          finding = details['findings'][finding_arn]
          if not instances.has_key(finding['assetAttributes']['agentId']): instances[finding['assetAttributes']['agentId']] = utilities.CoreDict()
          instances[finding['assetAttributes']['agentId']][finding_arn] = finding

        print "\nRUN: {}".format(details['runs'][run_arn]['name'])
        print "***********************************************************************"
        print "Instance ID\tNum. Findings\tProtected"
        print "***********************************************************************"
        for instance_id, findings in instances.items():
          instance_in_deepsecurity = dsm.computers.find(cloud_instance_id=instance_id)
          ds_instance_status = False
          if len(instance_in_deepsecurity) > 0: 
            ds_instance = dsm.computers[instance_in_deepsecurity[0]]
            ds_instance_status = True if ds_instance.computer_status_light == 'GREEN' or ds_instance.computer_status_light == 'YELLOW' else False

          print "{}\t{}\t{}".format(instance_id, len(findings), ds_instance_status)

          print details['findings'][u'arn:aws:inspector:us-west-2:518212039223:target/0-cgC3CGEj/template/0-fieTtmzZ/run/0-bXsK8Vbb/finding/0-nlPNDVCg']
