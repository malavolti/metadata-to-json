#!/usr/bin/env python 
#-*- coding: utf-8 -*-

import xml.etree.cElementTree as ET
from operator import itemgetter
from collections import OrderedDict

import sys, getopt
import json
import OpenSSL

OUTPUT="/opt/metadata-to-json/output"

def main(argv):
   try:
      # 'm:hd' means that 'm' needs an argument(confirmed by ':'), while 'h' and 'd' don't need it
      opts, args = getopt.getopt(sys.argv[1:], 'm:hd', ['metadata=','help','debug' ])
   except getopt.GetoptError as err:
      print str(err)
      print 'Usage: ./extractDataFromMD.py -m <md_inputfile>'
      print "The results will write into '%s/IDPs.txt', '%s/AAs.txt' and '%s/SPs.txt'" % (OUTPUT,OUTPUT,OUTPUT)
      sys.exit(2)

   inputfile = None
   idp_outputfile = None
   sp_outputfile = None

   for opt, arg in opts:
      if opt in ('-h', '--help'):
         print 'Usage: ./extractDataFromMD.py -m <md_inputfile>'
         print "The results will write into '%s/IDPs.txt', '%s/AAs.txt' and '%s/SPs.txt'" % (OUTPUT,OUTPUT,OUTPUT)
         sys.exit()
      elif opt in ('-m', '--metadata'):
         inputfile = arg
      elif opt == '-d':
         global _debug
         _debug = 1
      else:
         print 'Usage: ./extractDataFromMD.py -m <md_inputfile>'
         print "The results will write into '%s/IDPs.txt', '%s/AAs.txt' and '%s/SPs.txt'" % (OUTPUT,OUTPUT,OUTPUT)
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
      print 'Usage: ./extractDataFromMD.py -m <md_inputfile>'
      print "The results will write into '%s/IDPs.txt', '%s/AAs.txt' and '%s/SPs.txt'" % (OUTPUT,OUTPUT,OUTPUT)
      sys.exit()

   tree = ET.parse(inputfile)
   root = tree.getroot()
   idp = root.findall("./md:EntityDescriptor[md:IDPSSODescriptor]", namespaces)
   aa = root.findall("./md:EntityDescriptor[md:AttributeAuthorityDescriptor]", namespaces)
   sp = root.findall("./md:EntityDescriptor[md:SPSSODescriptor]", namespaces)

   sps = dict()
   idps = dict()
   aas = dict()

   list_idp = list()
   list_aa = list()
   list_sp = list()


   for EntityDescriptor in idp:

      ecs = 'NO EC SUPPORTED'
      pp_flag = 'Privacy Policy assente'
      info_flag = 'Info Page assente'
      logo_flag = 'Logo non presente'

      # Get entityID
      entityID = EntityDescriptor.get('entityID')

      # Get RegistrationAuthority
      regInfo = EntityDescriptor.find("./md:Extensions/mdrpi:RegistrationInfo", namespaces)
      regAuth = regInfo.get("registrationAuthority")

      # Get RegistrationInstant
      regInfo = EntityDescriptor.find("./md:Extensions/mdrpi:RegistrationInfo", namespaces)
      regInst = regInfo.get("registrationInstant")

      # Get EC Support
      entityCategories = EntityDescriptor.findall("./md:Extensions/mdattr:EntityAttributes/saml:Attribute[@Name='http://macedir.org/entity-category-support']/saml:AttributeValue", namespaces)
      saml_ecs = list()

      if (entityCategories != None):
          for samlAttrValue in entityCategories:
             if samlAttrValue.text != None:
                saml_ecs.append(samlAttrValue.text)

      if (len(saml_ecs) != 0):
          if 'http://refeds.org/category/research-and-scholarship' in saml_ecs:
             if 'http://www.geant.net/uri/dataprotection-code-of-conduct/v1' in saml_ecs:
                ecs = 'BOTH'
             else:
                ecs = "ONLY RS"
          elif 'http://www.geant.net/uri/dataprotection-code-of-conduct/v1' in saml_ecs:
             ecs = "ONLY COCO"
          else:
             ecs = "NO EC SUPPORTED"

      # Get scope
      scopes = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/shibmd:Scope[@regexp='false']", namespaces)
      idp_scopes = list()

      for scope in scopes:
         if scope.text != None:
            idp_scopes.append(scope.text)

      # Get MDUI Privacy Policy
      privacy_policies = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL", namespaces)
      pp_list = list()

      for pp in privacy_policies:
          lang = pp.get("{http://www.w3.org/XML/1998/namespace}lang")
          pp_list.append("%s - %s" % (lang,pp.text))

      if (len(pp_list) != 0):
          pp_flag = 'Privacy Policy presente'

      # Get MDUI Info Page
      info_pages = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:InformationURL", namespaces)
      info_list = list()

      for infop in info_pages:
          lang = infop.get("{http://www.w3.org/XML/1998/namespace}lang")
          info_list.append("%s - %s" % (lang,infop.text))

      if (len(info_list) != 0):
          info_flag = 'Info Page presente'

      # Get MDUI Logos
      logo_urls = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo", namespaces)
      logos_list = list()

      for logo in logo_urls:
          lang = logo.get("{http://www.w3.org/XML/1998/namespace}lang")
          width = logo.get("width")
          height = logo.get("height")
          logos_list.append("%s - %sx%s - %s" % (lang,width,height,logo.text))

      if (len(logos_list) != 0):
          logo_flag = 'Logo presente'

      # Get NameIDFormat
      nameIDformat = EntityDescriptor.findall("./md:IDPSSODescriptor/md:NameIDFormat", namespaces)
      name_id_formats = list()
    
      for nameid in nameIDformat:
         if nameid.text != None:
            name_id_formats.append(nameid.text)

      # Check Signing MD certificates
      cert_sign = EntityDescriptor.findall('md:IDPSSODescriptor/md:KeyDescriptor[@use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', namespaces)
      certs_sign = list()

      for cert in cert_sign:
         if cert.text != None:
            aux = "-----BEGIN CERTIFICATE-----"+cert.text+"-----END CERTIFICATE-----\n"
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, aux)
            certs_sign.append(x509.get_notAfter())

      # Check Encryption MD certificates
      cert_encr = EntityDescriptor.findall('md:IDPSSODescriptor/md:KeyDescriptor[@use="encryption"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', namespaces)
      certs_encr = list()

      for cert in cert_encr:
         if cert.text != None:
            aux = "-----BEGIN CERTIFICATE-----"+cert.text+"-----END CERTIFICATE-----\n"
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, aux)
            certs_encr.append(x509.get_notAfter())


      # Get technical contacts of an IdP
      technicalContactPerson = EntityDescriptor.findall("./md:ContactPerson[@contactType='technical']/md:EmailAddress", namespaces)
      supportContactPerson = EntityDescriptor.findall("./md:ContactPerson[@contactType='support']/md:EmailAddress", namespaces)

      technicalContacts = list()
      supportContacts = list()
      for tech in technicalContactPerson:
         if tech != None:
            if tech.text.startswith("mailto:"):
               technicalContacts.append(tech.text)
            else:
               technicalContacts.append("mailto:" + tech.text)      

      for supp in supportContactPerson:
         if supp != None:
            if supp.text.startswith("mailto:"):
               supportContacts.append(supp.text)
            else:
               supportContacts.append("mailto:" + supp.text)

      idp = OrderedDict ([
        ('entityID',entityID),
        ('scope',idp_scopes),
        ('registrationAuthority',regAuth),
        ('registrationInstant',regInst),
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
        ('supportContacts',supportContacts)
      ])


      list_idp.append(idp)
   
   result_idps = open(OUTPUT + "/IDPs.txt", "w")
   result_idps.write(json.dumps(sorted(list_idp,key=itemgetter('entityID')),sort_keys=False, indent=4))
   result_idps.close()

   for EntityDescriptor in aa:
      # Get entityID
      entityID = EntityDescriptor.get('entityID')   

      # Get RegistrationAuthority
      regInfo = EntityDescriptor.find("./md:Extensions/mdrpi:RegistrationInfo", namespaces)
      regAuth = regInfo.get("registrationAuthority")

      # Get RegistrationInstant
      regInfo = EntityDescriptor.find("./md:Extensions/mdrpi:RegistrationInfo", namespaces)
      regInst = regInfo.get("registrationInstant")

      # Get scope
      scopes = EntityDescriptor.findall("./md:AttributeAuthorityDescriptor/md:Extensions/shibmd:Scope[@regexp='false']", namespaces)
      aa_scopes = list()

      for scope in scopes:
         if scope.text != None:
            aa_scopes.append(scope.text)
    
      # Get NameIDFormat
      nameIDformat = EntityDescriptor.findall("./md:AttributeAuthorityDescriptor/md:NameIDFormat", namespaces)
      name_id_formats = list()
    
      for nameid in nameIDformat:
         if nameid.text != None:
            name_id_formats.append(nameid.text)

      aa = OrderedDict([
        ('entityID',entityID),
        ('registrationAuthority',regAuth),
        ('registrationInstant',regInst),
        ('scope',aa_scopes),
        ('NameIDFormat',name_id_formats)
      ]) 


      list_aa.append(aa)
   
   result_aas = open(OUTPUT + "/AAs.txt", "w")
   result_aas.write(json.dumps(sorted(list_aa, key=itemgetter('entityID')),sort_keys=False, indent=4))
   result_aas.close()

   for EntityDescriptor in sp:
      ecs = 'NO GLOBAL ECs'
      pp_flag = 'Privacy Policy assente'

      # Get entityID
      entityID = EntityDescriptor.get('entityID')

      # Get RegistrationAuthority
      regInfo = EntityDescriptor.find("./md:Extensions/mdrpi:RegistrationInfo", namespaces)
      regAuth = regInfo.get("registrationAuthority")

      # Get RegistrationInstant
      regInfo = EntityDescriptor.find("./md:Extensions/mdrpi:RegistrationInfo", namespaces)
      regInst = regInfo.get("registrationInstant")

      # Get EC Support
      entityCategories = EntityDescriptor.findall("./md:Extensions/mdattr:EntityAttributes/saml:Attribute[@Name='http://macedir.org/entity-category']/saml:AttributeValue", namespaces)
      saml_ecs = list()

      if (entityCategories != None):
          for samlAttrValue in entityCategories:
             if samlAttrValue.text != None:
                saml_ecs.append(samlAttrValue.text)

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
      nameIDformat = EntityDescriptor.findall("./md:SPSSODescriptor/md:NameIDFormat", namespaces)
      name_id_formats = list()

      if (nameIDformat != None):
         for nameid in nameIDformat:
            if nameid.text != None:
               name_id_formats.append(nameid.text)

      # Get MDUI Privacy Policy
      privacy_policies = EntityDescriptor.findall("./md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL", namespaces)
      pp_list = list()

      for pp in privacy_policies:
          lang = pp.get("{http://www.w3.org/XML/1998/namespace}lang")
          pp_list.append("%s:%s" % (lang,pp.text))

      if (len(pp_list) != 0):
          pp_flag = 'Privacy Policy presente'

      # Check Encryption MD certificates
      cert_encr = EntityDescriptor.findall('md:SPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate', namespaces)
      certs_encr = list()

      for cert in cert_encr:
         if cert.text != None:
            aux = "-----BEGIN CERTIFICATE-----"+cert.text+"-----END CERTIFICATE-----\n"
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, aux)
            certs_encr.append(x509.get_notAfter())

      # Get RequestedAttribute
      reqAttr = EntityDescriptor.findall("./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute", namespaces)
      requestedAttributes = list()

      if (reqAttr != None):
         for ra in reqAttr:
            auxDictAttr = {
                'FriendlyName':ra.get('FriendlyName'),
                'Name':ra.get('Name'),
                'NameFormat':ra.get('NameFormat'),
                'isRequired':ra.get('isRequired')
            }
            requestedAttributes.append(auxDictAttr) 
        

         sp = OrderedDict ([
            ('entityID',entityID),
            ('registrationAuthority',regAuth),
            ('registrationInstant',regInst),
            ('pp_flag', pp_flag),
            ('pp_list', pp_list),
            ('NameIDFormat',name_id_formats),
            ('cert_encr',certs_encr),
            ('RequestedAttribute',requestedAttributes),
            ('ecs_list',saml_ecs),
            ('ecs',ecs)
         ])

         list_sp.append(sp)
      
   result_sps = open(OUTPUT + "/SPs.txt", "w")
   result_sps.write(json.dumps(sorted(list_sp, key=itemgetter('entityID')),sort_keys=False,indent=4))
   result_sps.close()


if __name__ == "__main__":
   main(sys.argv[1:])
