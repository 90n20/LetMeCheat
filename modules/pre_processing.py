# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# module that returns all the avaliable samples
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#standard libraries
import os, logging

#local source
from . import config
from . import colors
from . import messages

#set logger name
logger = logging.getLogger(__name__)

class pre_processor():

    def process_dir(self, d):
        """
        Iterates over all the files inside a directory and return them as a list of paths
        if their size is greater than zero

        :param d: directory to check
        :return: List with paths to each of the samples avaliable in the specified directory
        """
        file_list = []
        for r, d, f in os.walk(d):
            for file in f:
                file_path = os.path.join(r, file)
                
                if (os.stat(file_path).st_size == 0) & config.DEBUG:
                    logger.info("skpipping empty file => %s" % file)

                file_list.append(file_path)

        return file_list


    def start(self):
        """
        Return all the avaliable files inside the directories specified in the
        configuration file

        :return: List with paths to each of the samples avaliable for analysis 
        """
        samples = []
        for d in config.data_dirs:
            messages.show(colors.BLUE, "[*]Processing directory {}...".format(d))
            tmp_list =  self.process_dir(d)
                        
            messages.show(colors.GREEN, "[*]%d files added." % len(tmp_list))
            samples += tmp_list

        return samples