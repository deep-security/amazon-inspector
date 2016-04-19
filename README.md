# Amazon Inspector

Use Deep Security to mitigate remotely exploitable findings made by Amazon Inspector via the command line or AWS Lambda.

**[19-Apr-2016 @ 10:15 CDT]**

Amazon Inspector was launched today at the AWS Summit in Chicago. We're finalizing the testing of the code base and will have an update available shortly. Please check back often.

## Index

- [Usage](#usage)
   - [coverage](#usage-coverage)
   - [analyze](#usage-analyze)
- [SSL Certificate Validation](#ssl-certificate-validation)

<a name="usage" />

### Usage

The syntax for basic command line usage is available by using the ```--help``` switch.

```bash
$ python ds-analyze-findings.py help
usage: ds-analyze-findings [COMMAND]
   For more help on a specific command, type ds-analyze-findings [COMMAND] --help

   Available commands:

   analyze
      > Analyze a set of Amazon Inspector findings
   coverage
      > Determine the coverage Deep Security has for Amazon Inspector findings

```

Each script in this set works under a common structure. There are several shared arguments;

```bash
  -h, --help            show this help message and exit
  -d DSM, --dsm DSM     The address of the Deep Security Manager. Defaults to
                        Deep Security as a Service
  --dsm-port DSM_PORT   The address of the Deep Security Manager. Defaults to
                        an AWS Marketplace/software install (:4119).
                        Automatically configured for Deep Security as a
                        Service
  -u DSM_USERNAME, --dsm-username DSM_USERNAME
                        The Deep Security username to access the IP Lists
                        with. Should only have read-only rights to IP lists
                        and API access
  -p DSM_PASSWORD, --dsm-password DSM_PASSWORD
                        The password for the specified Deep Security username.
                        Should only have read-only rights to IP lists and API
                        access
  -t DSM_TENANT, --dsm-tenant DSM_TENANT
                        The name of the Deep Security tenant/account
  -a AWS_ACCESS_KEY, --aws-access-key AWS_ACCESS_KEY
                        The access key for an IAM identity in the AWS account
                        to connect to
  -s AWS_SECRET_KEY, --aws-secret-key AWS_SECRET_KEY
                        The secret key for an IAM identity in the AWS account
                        to connect to
  -r AWS_REGION, --aws-region AWS_REGION
                        The name of AWS region to connect to                        
  --ignore-ssl-validation
                        Ignore SSL certification validation. Be careful when
                        you use this as it disables a recommended security
                        check. Required for Deep Security Managers using a
                        self-signed SSL certificate
  --dryrun              Do a dry run of the command. This will not make any
                        changes to your AWS WAF service
  --verbose             Enabled verbose output for the script. Useful for
                        debugging
```

These core settings allow you to connect to a Deep Security manager or Deep Security as a Service. 

```bash
# to connect to your own Deep Security manager
ds-analyze-findings.py [COMMAND] -d 10.1.1.0 -u admin -p USE_RBAC_TO_REDUCE_RISK --ignore-ssl-validation

# to connect to Deep Security as a Service
ds-analyze-findings.py [COMMAND] -u admin -p USE_RBAC_TO_REDUCE_RISK -t MY_ACCOUNT
```

Each individual command will also have it's own options that allow you to control the behaviour of the command.

You'll notice in the examples, the password is set to USE_RBAC_TO_REDUCE_RISK. In this context, RBAC stands for role based access control.

Currently Deep Security treats API access just like a user logging in. Therefore it is strongly recommended that you create a new Deep Security user for use with this script. This user should have the bare minimum permissions required to complete the tasks.

<a name="usage-coverage" />

### coverage

The coverage command will query the list of Amazon Inspector CVE coverage and compare it to the CVE's that Deep Security can mitigate. Remember that Deep Security focuses on the mitigate of *remotely exploitable* vulnerabilities using it's intrusion prevention engine.

```
# list the coverage available for Amazon Inspector + Deep Security
# ...for Deep Security as a Service
python ds-analyze-findings.py coverage -u WAF -p PASSWORD -t TENANT -l

# ...for another Deep Security manager
python ds-analyze-findings.py coverage -u WAF -p PASSWORD -d DSM_HOSTNAME --ignore-ssl-validation -l
```

This will generate output along the lines of;

```
***********************************************************************
* CVE Coverage
***********************************************************************
Amazon Inspector's rule set currently looks for 3203 CVEs
Deep Security's intrusion prevention rule set currently looks for 5076 CVEs

696 (21.73%) of the CVEs that Amazon Inspector looks for can be remotely mitigated by Deep Security

```

You can also use the ```--print-cve-only``` switch to generate a list of CVEs that fall under the coverage of both Amazon Inspector and Deep Security. That generates output along the lines of;

```
CVE-2009-2693
CVE-2009-2694
CVE-2009-2855
CVE-2009-2949
CVE-2009-2957
...
CVE-2015-4024
CVE-2015-4620
CVE-2015-5477
CVE-2015-5722
```

<a name="usage-analyze" />

### analyze


<a name="ssl-certificate-validation" />

## SSL Certificate Validation

If the Deep Security Manager (DSM) you're connecting to was installed via software of the AWS Marketplace, there's a chance that it is still using the default, self-signed SSL certificate. By default, python checks the certificate for validity which it cannot do with self-signed certificates.

If you are using self-signed certificates, please use the new ```--ignore-ssl-validation``` command line flag.

When you use this flag, you're telling python to ignore any certificate warnings. These warnings should be due to the self-signed certificate but *could* be for other reasons. It is strongly recommended that you have alternative mitigations in place to secure your DSM. 

When the flag is set, you'll see this warning block;

```bash
***********************************************************************
* IGNORING SSL CERTIFICATE VALIDATION
* ===================================
* You have requested to ignore SSL certificate validation. This is a less secure method 
* of connecting to a Deep Security Manager (DSM). Please ensure that you have other 
* mitigations and security controls in place (like restricting IP space that can access 
* the DSM, implementing least privilege for the Deep Security user/role accessing the 
* API, etc).
*
* During script execution, you'll see a number of "InsecureRequestWarning" messages. 
* These are to be expected when operating without validation. 
***********************************************************************
```

And during execution you may see lines similar to;

```python
.../requests/packages/urllib3/connectionpool.py:789: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
```

These are expected warnings. Can you tell that we (and the python core teams) are trying to tell you something? If you're interesting in using a valid SSL certificate, you can get one for free from [Let's Encrypt](https://letsencrypt.org), [AWS themselves](https://aws.amazon.com/certificate-manager/) (if your DSM is behind an ELB), or explore commercial options (like the [one from Trend Micro](http://www.trendmicro.com/us/enterprise/cloud-solutions/deep-security/ssl-certificates/)).