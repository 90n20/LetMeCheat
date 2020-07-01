# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# Module with global utilities
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#standard libraries
import sys, logging, hashlib

#third party libraries
import filetype, yara

#local source
from . import config

#set logger name
logger = logging.getLogger(__name__)

def get_sha256(content):
    return hashlib.sha256(content).hexdigest()

def is_PEFormat(data):
    """
    Method that tries to detect if a file as PE format based
    on its binary content

    :param data: sample binary content
    :return: True if sample has PE format, False otherwise
    """
    #data could be a file, bytes or bytes array

    file_type = filetype.guess(data)
    if file_type is None:
        if config.DEBUG:
            logger.info("File type can not be determined")
        return False
        
    return (filetype.guess(data).extension == "exe") \
        or (filetype.guess(data).extension == "dll") \
        or (filetype.guess(data).mime == "application/x-msdownload")
