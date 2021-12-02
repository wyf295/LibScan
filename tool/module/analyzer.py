# 执行分析的核心过程
import os
import config
import random
import multiprocessing


from config import LOGGER
from util import split_list_n_list

def get_methods_jar_map():
    methodes_jar = {}
    with open("conf/methodes_jar.txt", "r", encoding="utf-8") as file:
        for line in file.readlines():
            line = line.strip("\n")
            methodes_jar[line[:line.find(":")]] = line[line.find(":") + 1:]

    return methodes_jar

# 实现子进程提前反编译所有单个库
def sub_decompile_lib(libs, global_lib_info_dict, global_interface_libs_list, shared_lock_lib_info):
    # Logger.error("%s 开始运行...", process_name)

    for lib in libs:
        lib_info = decompile_lib_pre(lib_dex_folder, lib)
        shared_lock_lib_info.acquire()
        if len(lib_info) >=6 and not lib_info[6]:
            global_interface_libs_list.append(lib[:lib.rfind("-")])
        global_lib_info_dict[lib] = lib_info
        shared_lock_lib_info.release()

def search_lib_in_app(lib_folder = None,
                      apk_folder = None,
                      output_folder = 'outputs',
                      processes = None):
    methodes_jar = get_methods_jar_map()

    # 设置分析的cpu数量
    run_thread_num = processes if processes != None else config.run_thread_num
    LOGGER.info("分析使用的cpu数：%d", run_thread_num)

    LOGGER.info("开始提取所有库信息...")
    libs = os.listdir(lib_folder)
    random.shuffle(libs)
    # 定义全局库反编译结果，提前将单个库反编译并保存信息，需要时直接取，避免单个库被重复多次反编译
    global_lib_info_dict = multiprocessing.Manager().dict()
    # 定义对应共享锁
    shared_lock_lib_info = multiprocessing.Manager().Lock()
    # 记录在反编译提取信息过程中发现的所有纯接口的库
    global_interface_libs_list = multiprocessing.Manager().list()

    # 定义多进程将所有待检测的库全部反编译，并将node_dict保存到全局内存
    processes_list_decompile = []
    for sub_libs in split_list_n_list(libs, processes):
        thread = multiprocessing.Process(target=sub_decompile_lib,
                                         args=(sub_libs, global_lib_info_dict, global_interface_libs_list,
                                               shared_lock_lib_info))
        processes_list_decompile.append(thread)



