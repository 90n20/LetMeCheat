# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# Basic configurations for the proyect
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#standard libraries
import logging
import multiprocessing as mp

#third party libraries
import colorama

#set logger name
logger = logging.getLogger(__name__)

#debug status, change to false to reduce verbosity of logs
DEBUG = True
#Current version of the application
VERSION = '0.1'

#samples directories
unk_path = "/data/attachments_unknowncheats"
mpgh_path = "/data/attachments_mpgh"
data_dirs = [unk_path, mpgh_path]

#vt reports path
vt_path = "/data/vtReports"

#define avaliable cores. Always keep 2 cores unused or either use just 1
NCPU = mp.cpu_count() - 2 if mp.cpu_count() > 2 else 1

def init():
    #init logging utility
    logging.basicConfig(filename="LetMeCheat.log", level=logging.INFO)