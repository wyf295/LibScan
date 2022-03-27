# LibScan
------------------------
LibScan是一种最新的Android应用程序第三方库检测工具，能够在给定Android应用程序与第三方库二进制文件的情况
下检测应用程序中使用的库版本信息。

# 安装
------------------------
LibScan使用的python解释器版本为3.7.x，可以通过requirements.txt文件来安装依赖：
（使用的AndroGuard版本为3.4.0,使用的Dex2Jar版本为2.0，两者已被包含的tool文件夹下）
```
pip install -r requirements.txt
```

# 使用手册
------------------------
通过运行程序时添加参数detect_all -h，得到参数帮助文档如下：
```
usage: LibScan.py detect_all [-h] [-o FOLDER] [-p processes] [-af FOLDER]
                             [-lf FOLDER] [-ld FOLDER]

optional arguments:
  -h, --help    show this help message and exit
  -o FOLDER     指定结果输出文件夹
  -p processes  设置所有并行工作阶段的最大线程数（默认为当前工作机器的CPU核心数）
  -af FOLDER    指定一个apk文件夹
  -lf FOLDER    指定一个lib文件夹
  -ld FOLDER    指定库dex文件夹
```
举例：检测apks目录下的每个应用程序是否包含libs目录或者libs_dex目录下的每个库
（可以提供库的jar文件或者直接提供库转换好的dex文件）
```
$ ./LibScan.py detect_all -o outputs -af apks -lf libs -ld libs_dex
```

# 核心参数
------------------------
```
# 设置全局最大并行线程数
max_thread_num = multiprocessing.cpu_count() - 1

# 设置库级别检测"lib"或库版本级别检测"lib_version"（默认库版本级别，需要提供库与真实包名映射文件obf_tpl_pkg.csv）
detect_type = "lib_version"

# 类相似度阈值
class_similar = 0.7
# 库相似度阈值
lib_similar = 0.85

# 全局日志配置（默认INFO模式，改为DEBUG模式可输出各个匹配阶段的匹配结果到log文件
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(lineno)d] - %(message)s',
                    filename="log.txt",
                    filemode="a+")
LOGGER = logging.getLogger("console")
```

# 例子
------------------------
1、将data/ground_truth_apks文件夹下的com.linuxcounter.lico_update03.apk放入apks目录。

2、将data/ground_truth_libs_dex文件夹下的所有库转换好的dex文件放入libs_dex文件夹下，或者
将data/ground_truth_libs文件夹下的库jar文件放入libs文件夹下。

3、运行以下命令来检测com.linuxcounter.lico_update03.apk中是否包含data/ground_truth_libs下
的库。
```
$ ./LibScan.py detect_all -o outputs -af apks -lf libs -ld libs_dex
```
检测结果存在于outputs文件夹下的com.linuxcounter.lico_update03.apk.txt文件中，内容如下：
（结果文件包含检测出的库版本名称与对应的库相似度值，最后一行为该apk检测时间）
```
lib: com.android.support.gridlayout-v7.18.0.0
similarity: 1.0

lib: support-v4-18.0.0
similarity: 0.9995847803110373

lib: library-1.0.19 and com.mcxiaoke.volley.library.1.0.19
similarity: 1.0

time: 13s
```