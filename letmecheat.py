# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# Application entry point
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#standard libraries
import os, sys, time, logging

#third party libraries
import pandas as pd

#local source
from modules import config
from modules import banner
from modules import colors
from modules import messages
from modules.pre_processing import pre_processor
from modules.processing import processor

if __name__ == "__main__":
    #initialize configuration
    config.init()
    #set logger name
    logger = logging.getLogger(__name__)
    #show app banner
    banner.show()

    #initialize timer
    start = time.time()

    #pre-process samples
    pre = pre_processor()
    samples = pre.start()
    #initialize processor and process samples
    p = processor(samples)
    raw_data = p.start()

    #transform results to a pandas dataframe and save it as csv
    df = pd.DataFrame(raw_data)
    df.to_csv('samples_analyzed.csv', index = False, header=True)

    #stop timer and calculate elapsed time
    end = time.time()
    elapsed_time = end - start

    #print results
    messages.show(colors.GREEN, "[*]{} unique files processed in {} seconds".format(df.shape[0], elapsed_time))
