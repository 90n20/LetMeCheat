# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# Module to handle PE format structures
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#standard libraries
import math, collections, logging

#local source
from . import config

#set logger name
logger = logging.getLogger(__name__)

def imported_functions(pe):
    """
    Sample imported functions check

    :param data: pefile object
    :return: Number of imported functions
    :return: Number of unknown imported functions
    """
    unknown_imported_functions = 0
    imported_functions = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                #if there is no function name, probably coder is importing functions from a custom dll
                #or either importing functions by its address
                if not imp.name:
                    unknown_imported_functions += 1
                imported_functions.append(imp.name.decode("utf-8"))

    except Exception as e:
        if config.DEBUG:
            logger.info("File has no imports: {}".format(e))

    return unknown_imported_functions, imported_functions


def entropy(data):
    """
    Sample entropy calculation

    :param data: binary data
    :return: entropy value or 0 if it can't be calculated
    """

    if not data:
        return 0

    entropy = 0
    counter = collections.Counter(data)
    l = len(data)
    for count in counter.values():
        # count is always > 0
        p_x = count / l
        entropy += - p_x * math.log2(p_x)

    return entropy