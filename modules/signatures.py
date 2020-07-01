# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# Module to handle signatures and perform YARA scans
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#standard libraries
import os, sys, re, logging

#third party libraries
import yara

#set logger name
logger = logging.getLogger(__name__)

#signatures path
SIGNATURES_DIR = r'./signatures'

def match_signatures(sigfile):
    #it also calculates max sig score to perform other calculations
    signatures = []
    sig_filename = sigfile + ".sig"
    try:
        if sig_filename in os.listdir(SIGNATURES_DIR):
            #if exists, open signature file and read its lines
            with open(os.path.join(SIGNATURES_DIR, sig_filename), 'r', encoding='utf-8') as file:
                lines = file.readlines()
                for line in lines:
                    try:
                        #discard empty lines
                        if re.search(r'^[\s]*$', line):
                            continue

                        #discard comments
                        if re.search(r'^#', line):
                            continue

                        #signature data in the format sig;score;description
                        if ";" in line:
                            line = line.rstrip(" ").rstrip("\n\r")
                            sig_data = line.split(";")
                            signature = sig_data[0]
                            score = sig_data[1]
                            desc = sig_data[2]

                        #append signature data to a dictionary
                        sig = {'signature': signature, 'score': score, 'description': desc}
                        signatures.append(sig)
                    
                    except Exception as e:
                                logging.error("Error reading signature {}. Line: {}".format(signature, line))
                                return None

                #return generated dictionary
                return signatures

    except Exception as e:
        logging.error("Error reading signature file : %s" % sig_filename)
        return None



def match_yara_signatures(yara_file, raw_data):
    #YARA rules must be compiled before used
    rules = yara.compile(os.path.join(SIGNATURES_DIR, yara_file))
    #scan binary data using the compiled rules
    match = rules.match(data=raw_data)

    #For every match, record the number of hits on the binary
    total_hits = 0
    for rule_set in match:
        for i, hit in enumerate(rule_set.strings):
            total_hits += 1

    return total_hits