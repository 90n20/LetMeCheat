# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# Module that processes each sample
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
# -----------------------------------------------------------

#standard libraries
import multiprocessing as mp
import sys, logging

#third party libraries
from tqdm import tqdm
import pefile, filetype

#local source
from . import config
from . import colors
from . import messages
from .compressors import ZIPFile, RARFile, TARGZFile, TARFile
from . import pe
from . import signatures
from . import vt
from . import utils

#set logger name
logger = logging.getLogger(__name__)

class processor():

    def __init__(self, samples):
        """
        Class constructor

        :param samples: List with paths to each of the samples avaliable for analysis 
        """
        self.samples = samples

    def analyze_content(self, content):
        """
        core of the processing module. It receives the sample binary data and 
        sends it to the different processing modules.

        Final score for the sample is calculated based on different formulas and
        thresholds.

        :param content: sample binary data  
        :return: dictionary with sample analysis results
        """
        raw_data = {}
        final_score = 0

        #initialize pefile library with sample binary data
        pe_file = pefile.PE(data=content)

        #generate sample SHA256
        sha256 = utils.get_sha256(content)
        raw_data["sha256"] = sha256

        #calculate sample entropy
        entropy = pe.entropy(pe_file.__data__)
        raw_data["entropy"] = entropy

        #Add entropy score based on the following thresholds
        #4.347 => Plain text
        #5.099 => Native executables
        #6.801 => Packed executables
        #7.175 => Packed executables
        if (entropy <= 4.347):
            final_score += 0.25
        elif (entropy <= 5.099):
            final_score += 0.50
        elif (entropy <= 6.801):
            final_score += 0.75
        else:
            final_score += 1

        #encryption analysis using signsrch signatures
        encryption_hits = signatures.match_yara_signatures("signsrch.yara", content)
        raw_data["encryption_detected"] = 1 if (encryption_hits > 0) else 0

        #Add encyption score being 1 if detected and 0 if none
        final_score += 1 if (encryption_hits > 0) else 0
        
        #packers analysis using peid signatures
        packer_hits = signatures.match_yara_signatures("peid.yar", content)
        raw_data["packer_detected"] = 1 if (packer_hits > 0) else 0

        #Add packers score being 1 if detected and 0 if none
        final_score += 1 if (packer_hits > 0) else 0

        #imported functions analysis
        unknown_imported_functions, imported_functions = pe.imported_functions(pe_file)
        imported_functions_sigs = signatures.match_signatures("anticheat_techniques_imports")
        suspect_functions = 0
        max_score = 0
        imported_functions_score = 0
        for sig in imported_functions_sigs:
            max_score += int(sig["score"])
            for imported_function in imported_functions:
                if sig["signature"] in imported_function:
                    suspect_functions += 1
                    imported_functions_score += int(sig["score"])

        
        raw_data["suspect_imported_functions"] = suspect_functions
        raw_data["unknown_imported_functions"] = unknown_imported_functions

        #Add imported functions score in base 1 knowing that max score from current custom signatures is in max_score variable
        #this score is the 50% of the total score as it has the highest "value/cost" of the scoring system
        final_score += (imported_functions_score/max_score) * 5

        #Add unkown imported functions score being 1 if any hits and 0 if none
        final_score += 1 if (unknown_imported_functions > 0) else 0

        #analyze vt reports based on sample SHA256
        vt_hits = vt.get_vtResult(sha256)
        raw_data["vt_hits"] = vt_hits

        #Add vt score taking into account that a detected sample threshold is set in more than 5 detections
        if vt_hits is not None:
            final_score += 1 if (vt_hits > 5) else 0
        else:
            final_score += 0
        raw_data["final_score"] = final_score

        return raw_data

    def process_sample(self, f):
        """
        Checks sample filetype and decompress its contents in case its compressed. 
        If it is a PE format file, its binary content is processed.
        

        :param f: path of the sample  
        :return: dictionary with sample analysis results
        """
        valid = False
        try:
            #check sample filetype
            f_type = filetype.guess(f)
            if (f_type is None) & config.DEBUG:
                logger.info("unknwon filetype => %s" % f)
                return
            #if it has PE format, process it without further checks
            elif utils.is_PEFormat(f):
                entry = open(f, "rb")
                if entry is not None:
                    content = entry.read()
                    entry.close()
                    if content is not None:
                        valid = True
                        return self.analyze_content(content)
            else:
                #try to decompress each file that doesn't have a PE format using compressors module
                for cls in [ZIPFile, RARFile, TARGZFile, TARFile]:
                    if f_type.extension == cls.file_type:
                        cf = cls(f)
                        #check if content inside the compressed file has PE format
                        for content in cf.get_content:
                            if (content) or (content is not None):
                                if (utils.is_PEFormat(content)):
                                    valid = True
                                    return self.analyze_content(content)
                            
            if not valid & config.DEBUG:
                #logger.info("unsupported format: %s => %s" % (f_type.extension, f))
                logger.info("file or file contents are not PE format")
        except Exception as e:
            logger.error("line {} -> {} || {}".format(sys.exc_info()[-1].tb_lineno, e, f))


    def start(self):
        """
        Starts the processing module, initializing a thread pool based on the number of CPUs avaliable 
        on the analysis machine

        :return: List with analysis results of each sample
        """
        raw_data = []
        bar_format="{l_bar}%s{bar}%s{r_bar}" % (colors.YELLOW, colors.RESET)

        messages.show(colors.BLUE, "[*]Processing samples...")
        #initialize thread pool based on machine avaliable cores in order to process samples
        with mp.Pool(processes=config.NCPU) as p:
            max_ = len(self.samples)
            for res in tqdm(p.imap(self.process_sample, self.samples), total=max_, unit="samples", bar_format=bar_format):
                if res is not None:
                    raw_data.append(res)
        
        return raw_data