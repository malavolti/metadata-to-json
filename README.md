# metadata-to-json
Small python3 script that converts Metadata XML to JSON format

# Requirements

* `sudo apt install python3 python3-openssl python3-urllib3`
* `cd /opt ; sudo git clone https://github.com/malavolti/metadata-to-json.git`

# Cron Jobs
* Put the following command into your preferred CRON Jobs:
  * Choose ONE of the following command to consider only ONE metadata stream:
    * IDEM Test Metadata: 
      * `/usr/bin/wget http://md.idem.garr.it/metadata/idem-test-metadata-sha256.xml -O /opt/metadata-to-json/metadata/idem-test-metadata-sha256.xml >> /opt/metadata-to-json/logs/wget-idem-test.log 2>&1`
    * IDEM Production Metadata:
      * `/usr/bin/wget http://md.idem.garr.it/metadata/idem-metadata-sha256.xml -O /opt/metadata-to-json/metadata/idem-metadata-sha256.xml >> /opt/metadata-to-json/logs/wget-idem.log 2>&1`
    * EDUGAIN2IDEM Metadata:
      * `/usr/bin/wget http://md.idem.garr.it/metadata/edugain2idem-metadata-sha256.xml -O /opt/metadata-to-json/metadata/edugain2idem-metadata-sha256.xml >> /opt/metadata-to-json/logs/wget-edugain2idem.log 2>&1`

  * Use one of the following commands to generate EDS JSON file for the specific stream:
    * IDEM Test Metadata:
      * `/usr/bin/python3 /opt/metadata-to-json/extractDataFromMD.py -m /opt/metadata-to-json/metadata/idem-test-metadata-sha256.xml > /opt/metadata-to-json/logs/extractDataFromMD.log 2>&1`
    * IDEM Production Metadata:
      * `/usr/bin/python3 /opt/metadata-to-json/extractDataFromMD.py -m /opt/metadata-to-json/metadata/idem-metadata-sha256.xml > /opt/metadata-to-json/logs/extractDataFromMD.log 2>&1`
    * EDUGAIN2IDEM Metadata:
      * `/usr/bin/python3 /opt/metadata-to-json/extractDataFromMD.py -m /opt/metadata-to-json/metadata/edgugain2idem-metadata-sha256.xml > /opt/metadata-to-json/logs/extractDataFromMD.log 2>&1`

  Example Crontab:
  ```bash
     20 * * * * /usr/bin/wget http://md.idem.garr.it/metadata/edugain2idem-metadata-sha256.xml -O /opt/metadata-to-json/metadata/edugain2idem-metadata-sha256.xml > /opt/metadata-to-json/logs/wget-edugain2idem.log 2>&1

     21 * * * * /usr/bin/python3 /opt/metadata-to-json/extractDataFromMD.py -m /opt/metadata-to-json/metadata/edugain2idem-metadata-sha256.xml > /opt/metadata-to-json/logs/extractDataFromMD.log 2>&1
  ```
