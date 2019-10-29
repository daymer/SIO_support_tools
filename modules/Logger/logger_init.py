import logging
import os
from sys import platform
import re
from datetime import datetime
from modules.configuration import Integration
import warnings

# Suppressing DeprecationWarnings
warnings.filterwarnings("ignore")


def logging_config(integration_config: Integration, logging_mode: str= 'INFO', log_to_file: bool=False, executable_path: str = __file__) -> logging:
    formatter = logging.Formatter('%(asctime)s - %(name)s  - %(levelname)s - %(message)s')
    logger_inst = logging.getLogger()
    logger_inst.setLevel(logging_mode)
    if log_to_file is True:
        regex = r"[^\\\/](.+[\\\/])*(.+.+)$"
        matches = re.search(regex, executable_path)
        if matches:
            file_name = matches.group(2).replace('.py', '')
        else:
            file_name = 'unknown_process'
        log_name = integration_config.log_location + file_name + '_' + str(datetime.now().strftime("%Y-%m-%d_%H_%M_%S")) + '.log'
        try:
            previous_log_location = os.environ['sio_atm'].encode('latin1')
        except Exception:
            previous_log_location = 'none'
        if platform == "linux" or platform == "linux2":
            with open(os.path.expanduser("~/.bashrc"), "a") as outfile:
                # 'a' stands for "append"
                outfile.write("export sio_atm_old_log="+str(previous_log_location))
                outfile.write("export sio_atm_log=" + log_name)
        elif platform == "win32":
            # do nothing :)
            pass
        fh = logging.FileHandler(log_name)
        fh.setLevel(logging_mode)
        fh.setFormatter(formatter)
        logger_inst.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setLevel(logging_mode)
    ch.setFormatter(formatter)
    logger_inst.addHandler(ch)
    # Turning off the logging for some modules
    logging.getLogger("paramiko.transport").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    return logger_inst
