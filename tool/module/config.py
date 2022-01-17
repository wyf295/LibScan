import logging
import multiprocessing

# Operating parameters related config
# 定义运行的线程数
import sys

thread_num = multiprocessing.cpu_count() - 8

# 影响较大的参数：
# 当方法内opcode数量或者方法执行路径opcode数量大于该值时，不考虑（关键）
# max_opcode_len = sys.maxsize # 可调（基本确定）700

# 每opcode_error阈值位，允许有1位误差，低于该值，不允许有误差，该值越大，匹配要求的越严格
# opcode_error = sys.maxsize # 关键 25

#  apk方法中opcode数量不一定大于对应的库方法中的opcode数量，手动分析发现的
# apk_lib_method_opcode_rate = 0.8 # 未使用

# 在进行类粗粒度匹配时，app类中匹配方法的权重之和比上该类权重大于阈值class_similar，则视为类匹配
class_similar = 0.9 # 很关键（基本确定）
# lib_similar = 0.8

# 影响不大的参数：(对于无需修改的，后续直接在程序中定义，无需抽取成可配置参数）
# 如果大的类opcode数量是小的类opcode数量的opcode_mutiple倍，则直接不匹配，这就避免了一些仅包含小方法的apk类与很大的lib类完成了粗粒度匹配（关键）
# 可以自适应，当小类包含的opcode数量越多时
# opcode_mutiple = 2 # 一般不调

# 粗粒度极小匹配，无需进行细粒度匹配即可视为不包含该库
min_match = 0.1 # 可调

# 为接口或抽象类中没有方法体的方法赋予权重值参与得分计算
# abstract_method_weight = 3 # 一般不调


# Log related config
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(lineno)d] - %(message)s',
                    filename="log.txt",
                    filemode="a+")
LOGGER = logging.getLogger("console")