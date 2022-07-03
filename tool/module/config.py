# 核心配置
import logging
import multiprocessing

# Operating parameters related config
# Maximum number of processes used in detection:
max_thread_num = multiprocessing.cpu_count()

# Detection level: ("lib"=TPL level detection; "lib_version"=TPL version level detection)
# Default is TPL version level detection. Need to provide (TPL version,TPL) mapping in `conf/lib_name_map.csv` (We have provide the mapping for the ground truth dataset)
detect_type = "lib_version"

# class similarity threshold (theta)
class_similar = 0.7
# lib similarity threahold (theta2)
lib_similar = 0.85

# Global log configuration (INFO mode by default. Will output the phase-level matching results into log file when using DEBUG mode
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(lineno)d] - %(message)s',
                    filename="log.txt",
                    filemode="a+")
LOGGER = logging.getLogger("console")
