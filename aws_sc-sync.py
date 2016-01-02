#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This script will synchronize the AWS Public IPs with
# its corresponding SecurityCenter scan configuration

from __future__ import print_function
import json
import os
import requests
import yaml
from boto import ec2
from boto.ec2 import autoscale, regions
from boto.exception import BotoServerError, EC2ResponseError
from ConfigParser import ConfigParser
from collections import defaultdict
from sys import exit


_CONFIG_FILE_PATH = './'
_CONFIG_FILE = 'aws-config.cfg'

_AWS_CRED_FILE_PATH = './'
_AWS_CRED_FILE = 'aws-creds.yml'

_CREDENTIALS_FILE_PATH = './'
_CREDENTIALS_FILE = 'creds.yml'

# If instances are managed through scripting instead of AutoScale
# we can use their tagging to exclude them as needed
_FILTERS = [{'key': 'Name', 'value': 'autobots'},
  {'key': 'Name', 'value': 'xwy'}]

# Instance types that must be excluded
_INSTANCE_TYPES = ['micro', 'small']

# Define what text is prefixed to the AWS scans in SecurityCenter.
# For example, if you use the scan name AWS:WEB_PROD then here
# you would set the 'AWS'
_PREFIXED_SCAN_NAME = 'AWS'

config = ConfigParser()
config.read(os.path.join(_CONFIG_FILE_PATH, _CONFIG_FILE))

# Disable the "InsecureRequestWarning" error
requests.packages.urllib3.disable_warnings()


class SecurityCenterAdapter(object):

  def __init__(self):
    try:
      self.sc_server = config.get('SECURITYCENTER', 'sc_server')

    except Exception as e:
      print("Error: " + str(e))
      raise

    try:
      CREDENTIALS = yaml.load(
        file(os.path.join(_CREDENTIALS_FILE_PATH, _CREDENTIALS_FILE), 'r'))
    except IOError as e:
      print("Could not retrieve user credentials")
      raise

    SC_USERNAME = CREDENTIALS['sc_username']
    SC_PASSWORD = CREDENTIALS['sc_password']

    self.sc_session = requests.Session()

    # If SecurityCenter is using a self-signed certificate
    self.sc_session.verify = False

    data = {
      'username': SC_USERNAME, 'password': SC_PASSWORD
    }

    try:
      response = self.send_request_to_sc(module='token', method='POST', payload=data)
      if response:
        self.sc_session.headers.update({'X-SecurityCenter': response['response']['token']})

    except Exception as e:
      print("Error: " + str(e))
      raise

  def send_request_to_sc(self, module, method='GET', payload={}):

    sc_request_url = "{base}/{module}".format(base=self.sc_server, module=module)

    try:
      if method == 'GET':
        response = self.sc_session.get(sc_request_url, params=payload)
      elif method == 'POST':
        response = self.sc_session.post(sc_request_url, data=self.js_enc(payload))
      elif method == 'DELETE':
        response = self.sc_session.delete(sc_request_url, data=self.js_enc(payload))
      elif method == 'PATCH':
        response = self.sc_session.patch(sc_request_url, data=self.js_enc(payload))
      content = response.json()
      return content
    except Exception as e:
      print("[-] Unable To Send Request to SecurityCenter: {error}".format(error=e))
      return None

  def get_scan_list(self):

    data = {
      'fields': 'id,name'
    }

    try:
      response = self.send_request_to_sc(module='scan', method='GET', payload=data)
      if response['response']:
        return response['response']['usable']
      else:
        print(response['error_msg'])
        return None
    except Exception as e:
      print("[-] The request to obtain a scan list failed: {error}".format(error=e))
      return None

  def update_scan(self, scan, ip_list):

    module = 'scan/{scanID}'.format(scanID=scan['id'])

    ips = ','.join(ip_list)

    data = {
      'ipList': ips
    }

    response = self.send_request_to_sc(module=module, method='PATCH', payload=data)

    if response['response']:
      return response['response']
    else:
      print(response['error_msg'])
      return None

  def get_aws_scans(self):
    scans = self.get_scan_list()

    aws_scans = defaultdict(list)

    if scans:
      for scan in scans:
        # This looks for any scans in SecurityCenter
        # which match the prefixed name.
        if scan['name'].startswith(_PREFIXED_SCAN_NAME):
          scan_target = scan['name'].split(':')[1]
          aws_scans[scan_target].append(scan)

      return aws_scans

  def logout(self):
    return self.send_request_to_sc(module='token', method='DELETE')

  def js_enc(self, data):
    return json.dumps(data)


class AwsAdapter(object):

  def __init__(self):

    use_proxy = True

    use_proxy_credentials = True

    try:
      PROXY_SERVER = config.get('PROXY', 'proxy')
      PROXY_PORT = config.get('PROXY', 'proxy_port')
      if PROXY_SERVER == None or PROXY_PORT == None:
          raise Exception
      print("[+] Proxy Configuration found. Using proxy.")
    except Exception:
      print("[+] No Proxy Configuration in config file. Skipping Proxy.")
      use_proxy = False

    try:
      CREDENTIALS = yaml.load(
        file(os.path.join(_CREDENTIALS_FILE_PATH, _CREDENTIALS_FILE), 'r'))
    except IOError as e:
      print("[-] Could not retrieve credentials")
      exit()

    if use_proxy:
      try:
        PROXY_USER = CREDENTIALS['http_proxy_username']
        PROXY_PASSWORD = CREDENTIALS['http_proxy_password']
        print("[+] Proxy Credentials found.")
        if PROXY_USER == None or PROXY_PASSWORD == None:
          raise Exception
      except Exception:
        print("[+] No Proxy Credentials found. Assuming Proxy Doesn't Require Credentials.")
        use_proxy_credentials = False

    try:
      AWS_CREDENTIALS = yaml.load_all(file(_AWS_CRED_FILE_PATH + _AWS_CRED_FILE, 'r'))
      print("[+] Retrieved AWS credentials")
    except IOError:
      print("[-] Could not retrieve AWS credentials")
      raise

    regions = self.get_regions()

    self.region_ec2_mapping_dict = defaultdict(list)

    self.region_as_mapping_dict = defaultdict(list)

    for creds in AWS_CREDENTIALS:
      for k, v in creds.items():
        AWS_ACCESS_KEY_ID = creds[k]['aws_access_key_id']
        AWS_SECRET_ACCESS_KEY = creds[k]['aws_secret_access_key']
        for region in regions:
          try:
            print("[+] Attempting to establish an AWS Connection to {region} region.".format(region=region.name))
            if use_proxy:
              ec2_conn = ec2.connect_to_region(region.name, aws_access_key_id=AWS_ACCESS_KEY_ID,
              aws_secret_access_key=AWS_SECRET_ACCESS_KEY, is_secure=True, proxy=PROXY_SERVER,
              proxy_port=PROXY_PORT)
              as_conn = autoscale.connect_to_region(region.name, aws_access_key_id=AWS_ACCESS_KEY_ID,
              aws_secret_access_key=AWS_SECRET_ACCESS_KEY, is_secure=True, proxy=PROXY_SERVER,
              proxy_port=PROXY_PORT)
              if use_proxy_credentials:
                ec2_conn = ec2.connect_to_region(region.name, aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY, is_secure=True, proxy=PROXY_SERVER,
                proxy_port=PROXY_PORT, proxy_user=PROXY_USER, proxy_pass=PROXY_PASSWORD)
                as_conn = autoscale.connect_to_region(region.name, aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY, is_secure=True, proxy=PROXY_SERVER,
                proxy_port=PROXY_PORT, proxy_user=PROXY_USER, proxy_pass=PROXY_PASSWORD)
            else:
              ec2_conn = ec2.connect_to_region(region.name, aws_access_key_id=AWS_ACCESS_KEY_ID,
              aws_secret_access_key=AWS_SECRET_ACCESS_KEY, is_secure=True)
              as_conn = autoscale.connect_to_region(region.name, aws_access_key_id=AWS_ACCESS_KEY_ID,
              aws_secret_access_key=AWS_SECRET_ACCESS_KEY, is_secure=True)
          except Exception:
            print("[-] Unable to establish communications with AWS. Exiting.")
            exit()
          self.region_ec2_mapping_dict[k].append({'region': region.name, 'connectionEC2': ec2_conn})
          self.region_as_mapping_dict[k].append({'region': region.name, 'connectionAS': as_conn})

  def get_regions(self):
    return regions()

  def get_raw_instances(self):

    raw_ec2_instances = defaultdict(list)

    for entity in self.region_ec2_mapping_dict:
      print("[+] Retriving EC2 Instance data.")
      print("[+] AWS Account Name:", entity)
      for conn in self.region_ec2_mapping_dict[entity]:
        print("\t[+] AWS Region:", conn['region'])
        try:
          regional_ec2_instances = conn['connectionEC2'].get_all_reservations()
          if regional_ec2_instances:
            raw_ec2_instances[entity].extend(regional_ec2_instances)
        except EC2ResponseError as e:
          print("\t[-] Error retrieving EC2 instance data from {region}: {error}.".format(region=conn['region'], error=e.message))
    return raw_ec2_instances

  def extract_instance_info(self, raw_instances):

    processed_instances = defaultdict(list)

    for reservations in raw_instances:
      instances = [i.__dict__ for r in raw_instances[reservations] for i in r.instances]
      for i in instances:
        if 'ip_address' in i:
          instance_state = str(i['_state'])
          instance_type = str(i['instance_type'])
          instance_public_ip = str(i['ip_address'])
          if instance_state.find('running') != -1 and i['id'] not in self.as_instances_ids \
            and instance_type.split('.')[1] not in _INSTANCE_TYPES:
            filter_triggered = False
            for f in _FILTERS:
              if f['key'] in i['tags']:
                if i['tags'][f['key']].lower().find(f['value']) == -1:
                  pass
                else:
                  filter_triggered = True
                  break
            if filter_triggered is False:
              processed_instances[reservations].append(instance_public_ip)
    return processed_instances

  def extract_as_instance_id(self, raw_as_instances):

    self.as_instances_ids = []

    for as_instance in raw_as_instances:
      for i in raw_as_instances[as_instance]:
        as_ids = i.__dict__
        self.as_instances_ids.extend([as_ids['instance_id']])
    return

  def get_instances(self):
    # Retrieve all autoscale created instances
    raw_as_instances = self.get_autoscale_instances()

    # Populate the list with autoscale instance ids
    self.extract_as_instance_id(raw_as_instances)

    raw_ec2_instances = self.get_raw_instances()
    return self.extract_instance_info(raw_ec2_instances)

  def get_autoscale_instances(self):
    raw_as_instances = defaultdict(list)

    for entity in self.region_as_mapping_dict:
      print("[+] Retriving AutoScale data.")
      print("[+] AWS Account Name:", entity)
      for conn in self.region_as_mapping_dict[entity]:
        print("\t[+] AWS Region:", conn['region'])
        try:
          regional_as_instances = conn['connectionAS'].get_all_autoscaling_instances()
          if regional_as_instances:
            raw_as_instances[entity].extend(regional_as_instances)
        except (BotoServerError, EC2ResponseError) as e:
          print("\t[-] Error retrieving AutoScale data from {region}: {error}".format(region=conn['region'], error=e.message))

    return raw_as_instances


def main():

  aws = AwsAdapter()

  sc = SecurityCenterAdapter()

  aws_instances = aws.get_instances()

  sc_scans = sc.get_aws_scans()

  # This compares the AWS entity with the scan
  # name. If it matches then the scan is updated
  # with the latest AWS IP list
  if sc_scans:
    for scan in sc_scans:
      matched = False
      for instance in aws_instances:
        if scan == instance.upper():
          print("[+] {scan}:".format(scan=scan), len(aws_instances[instance]))
          print("\t IP Adresses:")
          for ip in aws_instances[instance]:
            print("\t\t{ip}".format(ip=ip))
          if len(aws_instances[instance]) > 0:
            sc.update_scan(sc_scans[scan][0], aws_instances[instance])
          matched = True
          break
      # If a match is not found for the AWS account name in SecurityCenter an error message is given
      if not matched:
          print("[-] No match found for scan name {prefix}:{scan}".format(prefix=_PREFIXED_SCAN_NAME, scan=scan))
  else:
    print("[-] No AWS related SecurityCenter scans found. Outputing AWS Public IPs discovered.")
    for instance in aws_instances:
      print("[+] {scan}:".format(scan=instance.upper()), len(aws_instances[instance]))
      print("\t IP Adresses:")
      for ip in aws_instances[instance]:
        print("\t\t{ip}".format(ip=ip))

  print("[+] Login out of SecurityCenter.")
  sc.logout()

if __name__ == "__main__":
  main()
  