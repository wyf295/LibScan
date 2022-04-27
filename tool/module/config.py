# 核心配置
import logging
import multiprocessing

# Operating parameters related config
# 设置全局最大并行线程数
max_thread_num = multiprocessing.cpu_count() - 1

# 设置库级别检测"lib"或库版本级别检测"lib_version"
# 默认库版本级别，需要在lib_name_map.csv文件中提供库与真实包名映射信息，用于确定库文件属于同一个库的不同版本
detect_type = "lib_version"

# 在进行类粗粒度匹配时，app类中匹配方法的权重之和比上该类权重大于阈值class_similar，则视为类匹配
class_similar = 0.7
# 设置库相似度，当库细粒度匹配的opcode数量与库总opcode数量比值大于该阈值，则视为包含，同时对于同一类库的不同版本，将该比值最大的视为真实包含的版本
lib_similar = 0.85

# 全局日志配置
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(lineno)d] - %(message)s',
                    filename="log.txt",
                    filemode="a+")
LOGGER = logging.getLogger("console")