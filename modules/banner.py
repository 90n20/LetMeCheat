# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# Module that prints the application banner
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#third party libraries
from art import *

#local source
from . import config
from . import colors
from . import messages

def show():
    """
    Shows the application banner, logo and version.
    """
    logo = text2art("Let Me Cheat!", font="nancyj-fancy")
    version = text2art("v" + config.VERSION, font="fancy20")
    messages.show(colors.MAGENTA, logo)
    messages.show(colors.YELLOW, version)
    messages.show(colors.LIGHTBLUE_EX, "Anti-Cheats Bypass Techniques Detector", "\n")
    messages.show(None, "##################################################################################")
    messages.show(colors.BLUE, "Master's Thesis")
    messages.show(colors.BLUE, "David Rodríguez Regueira")
    messages.show(None, "##################################################################################", "\n")