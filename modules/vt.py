# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# Module that processes each sample
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#standard libraries
import json, os, logging

#local source
from . import config

#set logger name
logger = logging.getLogger(__name__)

def get_vtResult(fhash):
    """
    Checks VirusTotal report from the specified sample (based on its sha256 hash) 
    if it is avaliable and return the number of detections.

    :param fhash: SHA256 hash of the sample being checked
    :return: antivirus matches from the VirusTotal report, None if no report avaliable
    """
    try:
        with open(os.path.join(config.vt_path, "{}.json".format(fhash))) as f:
            data = json.load(f)

        return data['data']['attributes']['last_analysis_stats']['malicious']

    except Exception as e:
        logger.error("Error reading VT report for {}".format(fhash))
        return None