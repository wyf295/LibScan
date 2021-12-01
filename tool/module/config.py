import logging


# Operating parameters related config
# 定义运行的线程数
run_thread_num = multiprocessing.cpu_count() - 4

# 影响较大的参数：
# 当方法内opcode数量或者方法执行路径opcode数量大于该值时，不考虑（关键）
max_opcode_len = 1500 # 可调（基本确定）

# 每opcode_error阈值位，允许有1位误差，低于该值，不允许有误差，该值越大，匹配要求的越严格
opcode_error = 10 # 关键

# apk方法中opcode数量不一定大于对应的库方法中的opcode数量，手动分析发现的
apk_lib_method_opcode_rate = 0.8

# 在进行类粗粒度匹配时，app类中匹配方法的权重之和比上该类权重大于阈值class_similar，则视为类匹配
class_similar = 0.8 # 很关键（基本确定）

# 影响不大的参数：(对于无需修改的，后续直接在程序中定义，无需抽取成可配置参数）
# 对过滤器中一个类中同一类信息出现次数设置记录上限
filter_record_limit = 10 # 不用调节

# 在提取类的方法hash值时，将方法中opcode数量小于min_method_opcode_num的方法直接排除（关键）
# 该阈值太小会导致apk类与lib类出现更多错误匹配，该阈值太大，说明只选中类中opcode数量比较多的方法参与匹配，会丢失apk中因方法死代码
# 消除而仅剩小方法的lib类，会丢失apk中与lib中本身只包含小方法的类（将该值调为6，就出现过不正确）
min_method_opcode_num = 0 # 一般不调

# 在进行具体的过滤比较之前，要求apk方法opcode数量必须>=库方法，但必须小于库方法的method_mutiple = 3倍。
method_mutiple = 3 # 一般不调

# 如果大的类opcode数量是小的类opcode数量的opcode_mutiple倍，则直接不匹配，这就避免了一些仅包含小方法的apk类与很大的lib类完成了粗粒度匹配（关键）
# 可以自适应，当小类包含的opcode数量越多时
opcode_mutiple = 2 # 一般不调

# 粗粒度极小匹配，无需进行细粒度匹配即可视为不包含该库
min_match = 0.1 # 可调

# 为接口或抽象类中没有方法体的方法赋予权重值参与得分计算
abstract_method_weight = 3 # 一般不调

# 最终确定库版本的阈值（关键：确定准备的版本）
lib_score_rate = 0.1 # 目前没用到
lib_opcode_rate = 0.3 # 目前没用到


# Log related config
logging.basicConfig(level=logging.ERROR,
                    format='%(asctime)s - %(name)s - [%(lineno)d] - %(message)s',
                    filename="抽样log/log_opcode_error_10.txt",
                    filemode="a+")
LOGGER = logging.getLogger("console")