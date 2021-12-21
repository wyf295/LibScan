# 程序启动入口

import os
import argparse
import datetime
import zipfile
import sys

from shutil import move
from module.config import LOGGER
from module.analyzer import search_lib_in_app

# 用户命令行输入参数解析
def parse_arguments():
    parser = argparse.ArgumentParser(description='Process some integers')
    subparsers = parser.add_subparsers(
        help='sub-command help', dest='subparser_name')

    parser_all = subparsers.add_parser(
        'detect_all', help='指定模式：检测apk中所有第三方库及版本号')
    parser_all.add_argument(
        '-o',
        metavar='FOLDER',
        type=str,
        default='outputs',
        help='指定结果输出目录')
    parser_all.add_argument(
        '-p',
        metavar='processes',
        type=int,
        default=None,
        help='设置所有并行工作阶段的最大线程数（默认为当前工作机器的CPU核心数）'
    )
    parser_all.add_argument(
        '-v',
        metavar='VERSION',
        type=str,
        default="INFO",
        help='设置日志输出级别，可选INFO/DEBUG'
    )
    parser_all.add_argument(
        '-af',
        metavar='FOLDER',
        type=str,
        help='指定一个apk目录'
    )
    parser_all.add_argument(
        '-ld',
        metavar='FOLDER',
        type=str,
        help='指定库生成的dex文件目录'
    )

    parser_specific = subparsers.add_parser(
        'detect_specific', help='指定模式：检测apk中是否存在具体的第三方库版本')
    parser_specific.add_argument(
        '-o',
        metavar='FOLDER',
        type=str,
        default='outputs',
        help='指定结果输出目录')
    parser_specific.add_argument(
        '-p',
        metavar='processes',
        type=int,
        default=None,
        help='设置所有并行工作阶段的最大线程数（默认为当前工作机器的CPU核心数）'
    )
    parser_specific.add_argument(
        '-v',
        metavar = 'VERSION',
        type=str,
        default="INFO",
        help='设置日志输出级别，可选INFO/DEBUG'
    )
    parser_specific.add_argument(
        '-af',
        metavar='FOLDER',
        type=str,
        help='指定一个apk目录')
    parser_specific.add_argument(
        '-lf',
        metavar='FOLDER',
        type=str,
        help='指定一个lib目录'
    )
    parser_specific.add_argument(
        '-ld',
        metavar='FOLDER',
        type=str,
        help='指定库生成的dex文件目录'
    )

    return parser.parse_args()

# 使用dex2jar工具将待检测的jar文件转换为dex文件
def jar_to_dex(libs_folder, lib_dex_folder):
    for file in os.listdir(libs_folder):
        file_name = file[:file.rfind(".")]
        cmd = "d2j-jar2dex.bat " + libs_folder + "/" + file + " -o " + libs_folder + "/" + file_name + ".dex"
        print("cmd: ", cmd)
        os.system(cmd)
    for file in os.listdir(libs_folder):
        if file.endswith(".dex"):
            move(libs_folder + "/" + file, lib_dex_folder + "/" + file)

# 将aar文件转换为jar文件
def arr_to_jar(libs_folder):
    for file in os.listdir(libs_folder):
        if file.endswith(".aar"):
            os.rename(libs_folder + "/" + file, libs_folder + "/" + file[:file.rfind(".")] + ".zip")

    for file in os.listdir(libs_folder):
        if file.endswith(".zip"):
            zip_file = zipfile.ZipFile(libs_folder + "/" + file)
            zip_file.extract("classes.jar", ".")
            for f in os.listdir(libs_folder):
                if f == "classes.jar":
                    os.rename(libs_folder + "/" + f, libs_folder + "/" + file[:file.rfind(".")] + ".jar")
            zip_file.close()
            os.remove(libs_folder+ "/" + file)

def main(lib_folder = None,
         lib_dex_folder = None,
         apk_folder = None,
         output_folder = 'outputs',
         processes = None):
    # 目前假设一定传入检测的库目录

    # 将库目录下所有的arr、jar文件转化为dex文件，并放入libs_dex目录下
    # arr_to_jar(lib_folder)
    # jar_to_dex(lib_folder, lib_dex_folder)

    search_lib_in_app(os.path.abspath(lib_dex_folder),
                      os.path.abspath(apk_folder),
                      os.path.abspath(output_folder),
                      processes)

if __name__ == '__main__':
    # print(sys.maxsize)
    sys.path.append('module/config')

    args = parse_arguments()
    LOGGER.setLevel(args.v)

    LOGGER.debug("args: %s", args)

    start_time = datetime.datetime.now()

    if args.subparser_name == 'detect_all':
        main(apk_folder = args.af, output_folder = args.o, processes = args.p, lib_dex_folder = args.ld)
    elif args.subparser_name == 'detect_specific':
        main(lib_folder = args.lf, lib_dex_folder = args.ld, apk_folder=args.af, output_folder= args.o, processes=args.p)
    else:
        LOGGER.error("检测模式输入错误!")

    end_time = datetime.datetime.now()
    print("检测耗时：%d（单位秒）" % ((end_time - start_time).seconds))