#!/usr/bin/env python 
#-*- coding: utf-8 -*-

import xml.etree.cElementTree as ET

import sys, getopt
import json

def main(argv):
   try:
      # 'i:x:y:hd' significa che 'i','x' e 'y' hanno bisogno di un argomento e viene segnato dal ':', mentre 'h' e 'd' non necessitano di argomenti
      opts, args = getopt.getopt(sys.argv[1:], 'm:hd', ['metadata=','help','debug' ])
   except getopt.GetoptError as err:
      print str(err)
      print 'Usage: ./extractDataFromMD.py -m <md_inputfile>'
      print 'The results will write into "output/IDPs.txt", "output/AAs.txt" and "outputSPs.txt"'
      sys.exit(2)

   inputfile = None
   idp_outputfile = None
   sp_outputfile = None

   for opt, arg in opts:
      if opt in ('-h', '--help'):
         print 'Usage: ./extractDataFromMD.py -m <md_inputfile>'
         print 'The results will write into "output/IDPs.txt", "output/AAs.txt" and "output/SPs.txt"'
         sys.exit()
      elif opt in ('-m', '--metadata'):
         inputfile = arg
      elif opt == '-d':
         global _debug
         _debug = 1
      else:
         print 'Usage: ./extractDataFromMD.py -m <md_inputfile>'
         print 'The results will write into "output/IDPs.txt", "output/AAs.txt" and "output/SPs.txt"'
         sys.exit()

   namespaces = {
      'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
      'mdrpi': 'urn:oasis:names:tc:SAML:metadata:rpi',
      'shibmd': 'urn:mace:shibboleth:metadata:1.0'
   }

   if inputfile == None:
      print 'Usage: ./extractDataFromMD.py -m <md_inputfile>'
      print 'The results will write into "output/IDPs.txt", "output/AAs.txt" and "output/SPs.txt"'
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
      # Get entityID
      entityID = EntityDescriptor.get('entityID')   

      # Get RegistrationAuthority
      regInfo = EntityDescriptor.find("./md:Extensions/mdrpi:RegistrationInfo", namespaces)
      regAuth = regInfo.get("registrationAuthority")

      # Get scope
      scopes = EntityDescriptor.findall("./md:IDPSSODescriptor/md:Extensions/shibmd:Scope[@regexp='false']", namespaces)
      idp_scopes = list()

      for scope in scopes:
         if scope.text != None:
            idp_scopes.append(scope.text)
    
      # Get NameIDFormat
      nameIDformat = EntityDescriptor.findall("./md:IDPSSODescriptor/md:NameIDFormat", namespaces)
      name_id_formats = list()
    
      for nameid in nameIDformat:
         if nameid.text != None:
            name_id_formats.append(nameid.text)

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

      idp = {
        'entityID':entityID,
        'scope':idp_scopes,
        'registrationAuthority':regAuth,
        'NameIDFormat':name_id_formats,
        'technicalContacts':technicalContacts,
        'supportContacts':supportContacts
      }


      list_idp.append(idp)
   
   result_idps = open("output/IDPs.txt", "w")
   result_idps.write(json.dumps(sorted(list_idp),sort_keys=True, indent=4))
   result_idps.close()

   for EntityDescriptor in aa:
      # Get entityID
      entityID = EntityDescriptor.get('entityID')   

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

      aa = {
        'entityID':entityID,
        'scope':aa_scopes,
        'NameIDFormat':name_id_formats,
      }


      list_aa.append(aa)
   
   result_aas = open("output/AAs.txt", "w")
   result_aas.write(json.dumps(sorted(list_aa),sort_keys=True, indent=4))
   result_aas.close()

   for EntityDescriptor in sp:
      # Get entityID
      entityID = EntityDescriptor.get('entityID')

      # Get NameIDFormat
      nameIDformat = EntityDescriptor.findall("./md:SPSSODescriptor/md:NameIDFormat", namespaces)
      name_id_formats = list()

      if (nameIDformat != None):
         for nameid in nameIDformat:
            if nameid.text != None:
               name_id_formats.append(nameid.text)

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
        

         sp = {
            'entityID':entityID,
            'NameIDFormat':name_id_formats,
            'RequestedAttribute':requestedAttributes
         }
         list_sp.append(sp)
      
   result_sps = open("output/SPs.txt", "w")
   result_sps.write(json.dumps(sorted(list_sp),sort_keys=True,indent=4))
   result_sps.close()


if __name__ == "__main__":
   main(sys.argv[1:])
