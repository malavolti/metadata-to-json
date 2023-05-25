#!/usr/bin/env python3 
#-*- coding: utf-8 -*-

import xml.etree.cElementTree as ET
from operator import itemgetter
from collections import OrderedDict

import sys, getopt
import json
import os
import OpenSSL
import urllib.request, socket
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
from jinja2 import Template

# timeout in seconds
timeout = 7
socket.setdefaulttimeout(timeout)

cwd = os.getcwd()
OUTPUT=cwd+"/output"

def getEntityID(EntityDescriptor, namespaces):
    return EntityDescriptor.get('entityID')


def getRegistrationAuthority(EntityDescriptor, namespaces):
    regInfo = EntityDescriptor.find("./md:Extensions/mdrpi:RegistrationInfo", namespaces)

    if (regInfo):
       return regInfo.get("registrationAuthority")
    else:
       return ''


def getRegistrationInstant(EntityDescriptor, namespaces):
    regInfo = EntityDescriptor.find("./md:Extensions/mdrpi:RegistrationInfo", namespaces)

    if (regInfo):
       return regInfo.get("registrationInstant")
    else:
       return ''


def getEntityCategories(EntityDescriptor, namespaces):
    saml_ecs = list()
    entityCategories = EntityDescriptor.findall("./md:Extensions/mdattr:EntityAttributes/saml:Attribute[@Name='http://macedir.org/entity-category-support']/saml:AttributeValue", namespaces)

    if (entityCategories != None):
       for samlAttrValue in entityCategories:
           if samlAttrValue.text != None:
              saml_ecs.append(samlAttrValue.text)
    return saml_ecs

# Get Scopes
def getScopes(EntityDescriptor,namespaces,entityType='idp'):

    scope_list = list()
    if (entityType.lower() == 'idp'):
       scopes = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/shibmd:Scope[@regexp='false']", namespaces)
    if (entityType.lower() == 'aa'):
       scopes = EntityDescriptor.findall("./md:AttributeAuthorityDescriptor/md:Extensions/shibmd:Scope[@regexp='false']", namespaces)

    for scope in scopes:
        if scope.text != None:
           scope_list.append(scope.text)
    
    return scope_list


# Get MDUI Privacy Policy and Check their availability
def getPrivacyStatementURLsAndCheckThem(EntityDescriptor,namespaces,entType='sp'):

    pp_list = list()
    if (entType.lower() == 'idp'):
       privacy_policies = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL", namespaces)
    if (entType.lower() == 'sp'):
       privacy_policies = EntityDescriptor.findall("./md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL", namespaces)

    for pp in privacy_policies:
        lang = pp.get("{http://www.w3.org/XML/1998/namespace}lang")
          
        status_pp_code = 200
        status_pp_reason = ""

        try:
           response = urllib.request.urlopen(pp.text,timeout=40)
        except URLError as e:
           if hasattr(e, 'reason'):
              status_pp_reason = e.reason
           if hasattr(e, 'code'):
              status_pp_code = e.code

        if (status_pp_reason):
           pp_list.append("%s - %s - %s - %s" % (str(status_pp_code),status_pp_reason,lang,pp.text))
        elif (status_pp_code != 200):
             pp_list.append("%s - %s - %s" % (str(status_pp_code),lang,pp.text))
        else:
             pp_list.append("%s - %s" % (lang,pp.text))

    return pp_list


# Get MDUI Keywords
def getKeywords(EntityDescriptor,namespaces,entType='idp'):

    kw_list = list()
    if (entType.lower() == 'idp'):
       keywords = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Keywords", namespaces)
    if (entType.lower() == 'sp'):
       keywords = EntityDescriptor.findall("./md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Keywords", namespaces)

    for kw in keywords:
        kw_dict = dict()
        kw_dict['value'] = kw.text
        kw_dict['lang'] = kw.get("{http://www.w3.org/XML/1998/namespace}lang")
        kw_list.append(kw_dict)

    return kw_list


# Get MDUI Privacy Policy
def getPrivacyStatementURLs(EntityDescriptor,namespaces,entType='idp'):

    pp_list = list()
    if (entType.lower() == 'idp'):
       privacy_policies = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL", namespaces)
    if (entType.lower() == 'sp'):
       privacy_policies = EntityDescriptor.findall("./md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL", namespaces)

    for pp in privacy_policies:
        pp_dict = dict()
        pp_dict['value'] = pp.text
        pp_dict['lang'] = pp.get("{http://www.w3.org/XML/1998/namespace}lang")
        pp_list.append(pp_dict)

    return pp_list


# Get MDUI Info Page and check them
def getInformationURLsAndCheckThem(EntityDescriptor,namespaces,entType='idp'):

    info_list = list()
    if (entType.lower() == 'idp'):
       info_pages = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:InformationURL", namespaces)
    if (entType.lower() == 'sp'):
       info_pages = EntityDescriptor.findall("./md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:InformationURL", namespaces)

    for infop in info_pages:
        lang = infop.get("{http://www.w3.org/XML/1998/namespace}lang")

        status_info_code = 200
        status_info_reason = ""

        try:
           response = urllib.request.urlopen(infop.text,timeout=40)
        except URLError as e:
           if hasattr(e, 'reason'):
              status_info_reason = e.reason
           if hasattr(e, 'code'):
              status_info_code = e.code

        if (status_info_reason):
           info_list.append("%s - %s - %s - %s" % (str(status_info_code),status_info_reason,lang,infop.text))
        elif(status_info_code != 200):
           info_list.append("%s - %s - %s" % (str(status_info_code),lang,infop.text))
        else:
           info_list.append("%s - %s" % (lang,infop.text))

    return info_list


# Get MDUI InformationURLs
def getInformationURLs(EntityDescriptor,namespaces,entType):

    info_list = list()
    if (entType.lower() == 'idp'):
       info_pages = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:InformationURL", namespaces)
    if (entType.lower() == 'sp'):
       info_pages = EntityDescriptor.findall("./md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:InformationURL", namespaces)

    for infop in info_pages:
        info_dict = dict()
        info_dict['value'] = infop.text
        info_dict['lang'] = infop.get("{http://www.w3.org/XML/1998/namespace}lang")
        info_list.append(info_dict)

    return info_list


# Get MDUI DisplayName
def getDisplayNames(EntityDescriptor,namespaces,entType='idp'):

    displayName_list = list()
    if (entType.lower() == 'idp'):
       displayNames = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName", namespaces)
    if (entType.lower() == 'sp'):
       displayNames = EntityDescriptor.findall("./md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName", namespaces)

    for dispName in displayNames:
        displayName_dict = dict()
        displayName_dict['value'] = dispName.text
        displayName_dict['lang'] = dispName.get("{http://www.w3.org/XML/1998/namespace}lang")
        displayName_list.append(displayName_dict)
    
    return displayName_list


# Get MDUI Descriptions
def getDescriptions(EntityDescriptor,namespaces,entType='idp'):

    description_list = list()
    if (entType.lower() == 'idp'):
       descriptions = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description", namespaces)
    if (entType.lower() == 'sp'):
       descriptions = EntityDescriptor.findall("./md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description", namespaces)

    for desc in descriptions:
        descriptions_dict = dict()
        descriptions_dict['value'] = desc.text
        descriptions_dict['lang'] = desc.get("{http://www.w3.org/XML/1998/namespace}lang")
        description_list.append(descriptions_dict)
    
    return description_list


# Get MDUI Logos
def getLogos(EntityDescriptor,namespaces,entType='idp'):

    logos_list = list()
    if (entType.lower() == 'idp'):
       logo_urls = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo", namespaces)
    if (entType.lower() == 'sp'):
       logo_urls = EntityDescriptor.findall("./md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo", namespaces)

    for logo in logo_urls:
        logo_dict = dict()
        logo_dict['value'] = logo.text
        logo_dict['width'] = logo.get("width")
        logo_dict['height'] = logo.get("height")
        logo_dict['lang'] = logo.get("{http://www.w3.org/XML/1998/namespace}lang")
        logos_list.append(logo_dict)

    return logos_list


# Get NameIDFormat
def getNameIDFormat(EntityDescriptor,namespaces,entType='idp'):

    name_id_formats = list()
    if (entType.lower() == 'idp'):
       nameIDformat = EntityDescriptor.findall("./md:IDPSSODescriptor/md:NameIDFormat", namespaces)
    if (entType.lower() == 'sp'):
       nameIDformat = EntityDescriptor.findall("./md:SPSSODescriptor/md:NameIDFormat", namespaces)
    if (entType.lower() == 'aa'):
       nameIDformat = EntityDescriptor.findall("./md:AttributeAuthorityDescriptor/md:NameIDFormat", namespaces)

    for nameid in nameIDformat:
        if nameid.text != None:
           name_id_formats.append(nameid.text)

    return name_id_formats


# Get MD Certificates
def getCerts(EntityDescriptor,namespaces,entType,certType=None):

    cert_list = list()
    if (entType.lower() == 'idp'):
       if (certType.lower() == 'signing'):
          # Check Signing MD certificates
          certs = EntityDescriptor.findall('./md:IDPSSODescriptor/md:KeyDescriptor[@use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', namespaces)
       if (certType.lower() == 'encryption'):
          certs = EntityDescriptor.findall('./md:IDPSSODescriptor/md:KeyDescriptor[@use="encryption"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', namespaces)
    if (entType.lower() == 'sp'):
      certs = EntityDescriptor.findall('./md:SPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate', namespaces)

    for crt in certs:
        if crt.text != None:
           aux = "-----BEGIN CERTIFICATE-----\n"+crt.text.strip()+"\n-----END CERTIFICATE-----\n"
           x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, aux)
           cert_list.append(str(x509.get_notAfter(), 'utf-8'))

    return cert_list


# Get Contacts
def getContacts(EntityDescriptor,namespaces,contactType):
    
    contact_list = list()
    if (contactType.lower() == 'technical'):
       contacts = EntityDescriptor.findall("./md:ContactPerson[@contactType='technical']/md:EmailAddress", namespaces)
    if (contactType.lower() == 'support'):
       contacts = EntityDescriptor.findall("./md:ContactPerson[@contactType='support']/md:EmailAddress", namespaces)
    for ctc in contacts:
        if ctc != None:
           if ctc.text.startswith("mailto:"):
              contact_list.append(ctc.text)
           else:
              contact_list.append("mailto:" + ctc.text)      

    return contact_list


# Get EncryptionMethod of SPs
def getEncryptionMethods(EntityDescriptor,namespaces):
    
    enc_method_list = list()
    enc_methods = EntityDescriptor.findall("./md:SPSSODescriptor/md:KeyDescriptor/md:EncryptionMethod", namespaces)
    
    if (enc_methods):
       for enc_mtd in enc_methods:
           em = enc_mtd.get("Algorithm")
           em_value = em.split("#")[1]
           enc_method_list.append(em_value)

    return enc_method_list


# Get SP supporting AES128-GCM
def hasGCM(EntityDescriptor,namespaces):
    gcm = EntityDescriptor.find("./md:SPSSODescriptor/md:KeyDescriptor/md:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm']", namespaces)
    if (gcm != None):
       return True
    else:
       return False

# Get OrganizationName List
def getOrgNames(EntityDescriptor,namespaces):

    orgName_list = list()
    orgName_urls = EntityDescriptor.findall("./md:Organization/md:OrganizationName", namespaces)

    for orgName in orgName_urls:
        orgName_dict = dict()
        orgName_dict['value'] = orgName.text
        orgName_dict['lang'] = orgName.get("{http://www.w3.org/XML/1998/namespace}lang")
        orgName_list.append(orgName_dict)

    return orgName_list

# Get OrganizationDisplayName List
def getOrgDisplayNames(EntityDescriptor,namespaces):

    orgDisplayName_list = list()
    orgDisplayName_urls = EntityDescriptor.findall("./md:Organization/md:OrganizationDisplayName", namespaces)

    for orgDisplayName in orgDisplayName_urls:
        orgDisplayName_dict = dict()
        orgDisplayName_dict['value'] = orgDisplayName.text
        orgDisplayName_dict['lang'] = orgDisplayName.get("{http://www.w3.org/XML/1998/namespace}lang")
        orgDisplayName_list.append(orgDisplayName_dict)

    return orgDisplayName_list


# Get OrganizationURL List
def getOrgURLs(EntityDescriptor,namespaces):

    orgUrl_list = list()
    orgUrl_urls = EntityDescriptor.findall("./md:Organization/md:OrganizationURL", namespaces)

    for orgUrl in orgUrl_urls:
        orgUrl_dict = dict()
        orgUrl_dict['value'] = orgUrl.text
        orgUrl_dict['lang'] = orgUrl.get("{http://www.w3.org/XML/1998/namespace}lang")
        orgUrl_list.append(orgUrl_dict)

    return orgUrl_list


def main(argv):
   try:
      # 'm:hd' means that 'm' needs an argument(confirmed by ':'), while 'h' and 'd' don't need it
      opts, args = getopt.getopt(sys.argv[1:], 'm:hd', ['metadata=','help','debug' ])
   except getopt.GetoptError as err:
      print (str(err))
      print ('Usage: ./extractDataFromMD.py -m <md_inputfile>')
      print ("The results will write into '%s/IDPs.json', '%s/AAs.json' and '%s/SPs.json'" % (OUTPUT,OUTPUT,OUTPUT))
      sys.exit(2)

   inputfile = None
   idp_outputfile = None
   sp_outputfile = None

   for opt, arg in opts:
      if opt in ('-h', '--help'):
         print ('Usage: ./extractDataFromMD.py -m <md_inputfile>')
         print ("The results will write into '%s/IDPs.json', '%s/AAs.json' and '%s/SPs.json'" % (OUTPUT,OUTPUT,OUTPUT))
         sys.exit()
      elif opt in ('-m', '--metadata'):
         inputfile = arg
      elif opt == '-d':
         global _debug
         _debug = 1
      else:
         print ('Usage: ./extractDataFromMD.py -m <md_inputfile>')
         print ("The results will write into '%s/IDPs.json', '%s/AAs.json' and '%s/SPs.json'" % (OUTPUT,OUTPUT,OUTPUT))
         sys.exit()

   namespaces = {
      'xml':'http://www.w3.org/XML/1998/namespace',
      'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
      'mdrpi': 'urn:oasis:names:tc:SAML:metadata:rpi',
      'shibmd': 'urn:mace:shibboleth:metadata:1.0',
      'mdattr': 'urn:oasis:names:tc:SAML:metadata:attribute',
      'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      'ds': 'http://www.w3.org/2000/09/xmldsig#',
      'mdui': 'urn:oasis:names:tc:SAML:metadata:ui'
   }

   if inputfile == None:
      print ('Usage: ./extractDataFromMD.py -m <md_inputfile>')
      print ("The results will write into '%s/IDPs.json', '%s/AAs.json' and '%s/SPs.json'" % (OUTPUT,OUTPUT,OUTPUT))
      sys.exit()

   tree = ET.parse(inputfile)
   root = tree.getroot()
   idp = root.findall("./md:EntityDescriptor[md:IDPSSODescriptor]", namespaces)
   aa = root.findall("./md:EntityDescriptor[md:AttributeAuthorityDescriptor]", namespaces)
   sp = root.findall("./md:EntityDescriptor[md:SPSSODescriptor]", namespaces)

   sps = dict()
   idps = dict()
   aas = dict()

   list_eds = list()
   list_idp = list()
   list_aa = list()
   list_sp = list()
   list_default_gcm_sp = list()
   list_eds = list()

   # IDPSSODescriptor
   for EntityDescriptor in idp:

      ecs = "NO EC SUPPORTED"
      pp_flag = "Privacy Policy assente"
      info_flag = "Info Page assente"
      logo_flag = "Logo non presente"

      # Get entityID
      entityID = getEntityID(EntityDescriptor,namespaces)

      # Get FQDN
      fqdn = urlparse(entityID).netloc

      # Get FQDN
      hostname = fqdn.split('.')[0]

      # Get RegistrationAuthority
      regAuth = getRegistrationAuthority(EntityDescriptor,namespaces)

      # Get RegistrationInstant
      regInst = getRegistrationInstant(EntityDescriptor,namespaces)

      # Get MDUI DisplayName
      displayName_list = getDisplayNames(EntityDescriptor,namespaces,'idp')

      # Get MDUI Descriptions
      description_list = getDescriptions(EntityDescriptor,namespaces,'idp')

      # Get MDUI Keywords
      keyword_list = getKeywords(EntityDescriptor,namespaces,'idp')

      # Get EC Support
      saml_ecs = getEntityCategories(EntityDescriptor,namespaces)

      if (len(saml_ecs) != 0):
          if 'http://refeds.org/category/research-and-scholarship' in saml_ecs:
             if 'http://www.geant.net/uri/dataprotection-code-of-conduct/v1' in saml_ecs:
                ecs = 'BOTH'
             else:
                ecs = "ONLY RS"
          elif 'http://www.geant.net/uri/dataprotection-code-of-conduct/v1' in saml_ecs:
             ecs = "ONLY COCO"

      # Get scope
      idp_scopes = getScopes(EntityDescriptor,namespaces,'idp')

      # Get MDUI Privacy Policy
      pp_list = getPrivacyStatementURLs(EntityDescriptor,namespaces,'idp')
      #pp_list = getPrivacyStatementURLsAndCheckThem(EntityDescriptor,namespaces,'idp')

      if (len(pp_list) != 0):
         pp_flag = 'Privacy Policy presente'

      # Get MDUI Info Page
      info_list = getInformationURLs(EntityDescriptor,namespaces,'idp')
      #info_list = getInformationURLsAndCheckThem(EntityDescriptor,namespaces,'idp')

      if (len(info_list) != 0):
         info_flag = 'Information Page presente'

      # Get MDUI Logos
      logos_list = getLogos(EntityDescriptor,namespaces,'idp')

      if (len(logos_list) != 0):
         logo_flag = 'Logo presente'

      # Get NameIDFormat
      name_id_formats = getNameIDFormat(EntityDescriptor,namespaces,'idp')
    
      # Check Signing MD certificates
      certs_sign = getCerts(EntityDescriptor,namespaces,'idp','signing')

      # Check Encryption MD certificates
      certs_encr = getCerts(EntityDescriptor,namespaces,'idp','encryption')

      # Get technical contacts of an IdP
      technicalContacts = getContacts(EntityDescriptor,namespaces,'technical')
      supportContacts = getContacts(EntityDescriptor,namespaces,'support')

      # Get OrganizationUrl
      orgUrl_list = getOrgURLs(EntityDescriptor,namespaces)

      idp = OrderedDict ([
        ('entityID',entityID),
        ('scope',idp_scopes),
        ('registrationAuthority',regAuth),
        ('registrationInstant',regInst),
        ('DisplayNames',displayName_list),
        ('Descriptions',description_list),
        ('Keywords',keyword_list),
        ('pp_flag', pp_flag),
        ('pp_list', pp_list),
        ('info_flag', info_flag),
        ('info_list', info_list),
        ('logo_flag', logo_flag),
        ('logos_list', logos_list),
        ('ecs_list',saml_ecs),
        ('ecs',ecs),
        ('md_certs_sign',certs_sign),
        ('md_certs_encr',certs_encr),
        ('NameIDFormat',name_id_formats),
        ('technicalContacts',technicalContacts),
        ('supportContacts',supportContacts),
        ('organizationURL',orgUrl_list)
      ])

      list_idp.append(idp)

      eds = OrderedDict([
        ('entityID',entityID),
        ('DisplayNames',displayName_list),
        ('Descriptions',description_list),
        ('Keywords',keyword_list),
        ('PrivacyStatementURLs', pp_list),
        ('InformationURLs', info_list),
        ('Logos', logos_list)
      ])

      list_eds.append(eds)

      if (len(orgUrl_list) < 2):
         orgUrl_dict = dict()
         orgUrl_dict['lang'] = ""
         orgUrl_list.append(orgUrl_dict)

   result_idps = open(OUTPUT + "/IDPs.json", "w")
   result_idps.write(json.dumps(sorted(list_idp,key=itemgetter('entityID')),sort_keys=False, indent=4, ensure_ascii=False))
   result_idps.close()

   with open(OUTPUT + "/EDS.json", "w",encoding=None) as result_eds:
    result_eds.write(json.dumps(sorted(list_eds,key=itemgetter('entityID')),sort_keys=False, indent=4, ensure_ascii=False))
    result_eds.close()


   # AADescriptor
   for EntityDescriptor in aa:

      # Get entityID
      entityID = getEntityID(EntityDescriptor,namespaces)   

      # Get FQDN
      fqdn = urlparse(entityID).netloc

      # Get RegistrationAuthority
      regAuth = getRegistrationAuthority(EntityDescriptor,namespaces)

      # Get RegistrationInstant
      regInst = getRegistrationInstant(EntityDescriptor,namespaces)

      # Get scope
      aa_scopes = getScopes(EntityDescriptor,namespaces,'aa')

      # Get NameIDFormat
      name_id_formats = getNameIDFormat(EntityDescriptor,namespaces,'aa')

      aa = OrderedDict([
        ('entityID',entityID),
        ('registrationAuthority',regAuth),
        ('registrationInstant',regInst),
        ('scope',aa_scopes),
        ('NameIDFormat',name_id_formats)
      ]) 

      list_aa.append(aa)
   
   result_aas = open(OUTPUT + "/AAs.json", "w")
   result_aas.write(json.dumps(sorted(list_aa, key=itemgetter('entityID')),sort_keys=False, indent=4, ensure_ascii=False))
   result_aas.close()

   # SPSSODescriptor
   for EntityDescriptor in sp:
      ecs = 'NO GLOBAL ECs'
      pp_flag = 'Privacy Policy assente'

      # Get entityID
      entityID = EntityDescriptor.get('entityID')

      # Get RegistrationAuthority
      regAuth = getRegistrationAuthority(EntityDescriptor,namespaces)

      # Get RegistrationInstant
      regInst = getRegistrationInstant(EntityDescriptor,namespaces)

      # Get MDUI DisplayName
      displayName_list = getDisplayNames(EntityDescriptor, namespaces, 'sp')

      # Get MDUI Descriptions
      description_list = getDescriptions(EntityDescriptor, namespaces, 'sp')

      # Get MDUI Keywords
      keyword_list = getKeywords(EntityDescriptor, namespaces,'sp')

      # Get EC Support
      saml_ecs = getEntityCategories(EntityDescriptor,namespaces)

      if (len(saml_ecs) != 0):
          if 'http://refeds.org/category/research-and-scholarship' in saml_ecs:
             if 'http://www.geant.net/uri/dataprotection-code-of-conduct/v1' in saml_ecs:
                ecs = 'BOTH'
             else:
                ecs = "ONLY RS"
          elif 'http://www.geant.net/uri/dataprotection-code-of-conduct/v1' in saml_ecs:
             ecs = "ONLY COCO"
          else:
             ecs = "NO GLOBAL EC"

      # Get NameIDFormat
      name_id_formats = getNameIDFormat(EntityDescriptor,namespaces,'sp')

      # Get MDUI Privacy Policy
      pp_list = getPrivacyStatementURLs(EntityDescriptor,namespaces,'sp')

      if (len(pp_list) != 0):
         pp_flag = 'Privacy Policy presente'

      # Check Encryption MD certificates
      certs_encr = getCerts(EntityDescriptor,namespaces,'sp')

      # Get EncryptionMethods
      enc_mtds = getEncryptionMethods(EntityDescriptor,namespaces)

      # Get RequestedAttribute
      reqAttr = EntityDescriptor.findall("./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute", namespaces)
      requestedAttributes = list()

      # Get Require eduPersonTargetedID
      req_eptid = 0
      req_persistent_nameid = 0

      if (reqAttr != None):
         for ra in reqAttr:
            auxDictAttr = {
                'FriendlyName':ra.get('FriendlyName'),
                'Name':ra.get('Name'),
                'NameFormat':ra.get('NameFormat'),
                'isRequired':ra.get('isRequired')
            }
            requestedAttributes.append(auxDictAttr) 

            if (ra.get('Name') == 'urn:oid:1.3.6.1.4.1.5923.1.1.1.10' and ra.get('isRequired') == 'true'): req_eptid = 1
            if (name_id_formats):
               if ('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' == name_id_formats[0]): req_persistent_nameid = 1
        

      sp = OrderedDict ([
            ('entityID',entityID),
            ('DisplayName',displayName_list),
            ('registrationAuthority',regAuth),
            ('registrationInstant',regInst),
            ('pp_flag', pp_flag),
            ('pp_list', pp_list),
            ('NameIDFormat',name_id_formats),
            ('req_eptid',req_eptid),
            ('req_persistent_nameid',req_persistent_nameid),
            ('cert_encr',certs_encr),
            ('enc_mtds',enc_mtds),
            ('RequestedAttribute',requestedAttributes),
            ('ecs_list',saml_ecs),
            ('ecs',ecs)
      ])

      list_sp.append(sp)

      isSPgcm = hasGCM(EntityDescriptor,namespaces)

      # Create a list with SPs that doesn't have any EncryptionMethods into their Metadata
      # or that doesn't have the new AES128-GCM algorithm into their EncryptionMethods
      if ((not enc_mtds) or (not isSPgcm)):
         no_enc_mtds_sp = OrderedDict ([
            ('entityID',entityID),
            ('registrationAuthority',regAuth),
         ])
         
         list_default_gcm_sp.append(no_enc_mtds_sp)

   result_sps = open(OUTPUT + "/SPs.json", "w")
   result_sps.write(json.dumps(sorted(list_sp, key=itemgetter('entityID')),sort_keys=False,indent=4, ensure_ascii=False))
   result_sps.close()

   default_gcm_sps = open(OUTPUT + "/default-gcm-sps.json", "w")
   default_gcm_sps.write(json.dumps(sorted(list_default_gcm_sp, key=itemgetter('entityID')),sort_keys=False,indent=4, ensure_ascii=False))
   default_gcm_sps.close()



if __name__ == "__main__":
   main(sys.argv[1:])
