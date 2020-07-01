# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# Module for printing messages
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#local source
from . import colors

def show(color, message, end=None):
    """
    prints a message in console with custom color and linebreak

    :param color: desired output color
    :param message: message to be printed
    :param end: desired linebreak
    """
    if color:
        print("%s%s%s" % (
            color,
            message,
            colors.END
        ))
    else:
        print(message)
    if end: 
        print(end)