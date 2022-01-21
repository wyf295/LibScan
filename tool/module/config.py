import logging
import multiprocessing

# Operating parameters related config
# 设置全局最大并行线程数
max_thread_num = multiprocessing.cpu_count() - 8

# 设置库级别检测"lib"或库版本级别检测"lib_version"（默认库版本级别，需要提供库与真实包名映射文件obf_tpl_pkg.csv）
detect_type = "lib_version"

# 在进行类粗粒度匹配时，app类中匹配方法的权重之和比上该类权重大于阈值class_similar，则视为类匹配
class_similar = 0.7 # 很关键（基本确定）
# 设置库相似度，当库细粒度匹配的opcode数量与库总opcode数量比值大于该阈值，则视为包含，同时对于同一类库的不同版本，将该比值最大的视为真实包含的版本
lib_similar = 0.85

# 粗粒度极小匹配，无需进行细粒度匹配即可视为不包含该库，因为粗粒度匹配会为库中的每个类找出多个粗粒度匹配的应用程序类，
# 而细粒度匹配是从这多个粗粒度匹配的应用程序类中找出真实匹配的一个类，最终再根据成功被细粒度匹配的库类情况来决定应用程序是否包含库
# 所以库粗粒度匹配相似度值只会大于等于细粒度匹配相似度值
# min_match = lib_similar

# 全局日志配置
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(lineno)d] - %(message)s',
                    filename="log.txt",
                    filemode="a+")
LOGGER = logging.getLogger("console")