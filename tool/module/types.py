# 定义程序中使用到的一些常量
from enum import Enum, unique


@unique
class Constant(Enum):
    # 类标志常量
    ZERO = "0x0"
    PUBLIC = "public"
    INTERFACE = "interface"
    ABSTRACT = "abstract"
    ENUM = "enum"
    STATIC = "static"

    # 类型常量
    JAVA_TYPE = "Ljava/"
    ARR = "["
    JAVA_ARR = "[Ljava/"
    OBJECT = "Ljava/lang/Object;"
    STRING = "Ljava/lang/String"
    JAVA_BASIC_TYPE = ["B", "S", "I", "J", "F", "D", "Z", "C"]
    JAVA_BASIC_TYPR_DICT = {"B": 4, "S": 5, "I": 6, "J": 7, "F": 8, "D": 9, "Z": 10, "C": 11}
    JAVA_BASIC_TYPR_ARR_DICT = {"[B": 13, "[S": 14, "[I": 15, "[J": 16, "[F": 17, "[D": 18, "[Z": 19, "[C": 20}
    RETURN_JAVA_BASIC_TYPR_DICT = {"B": 4, "S": 5, "I": 6, "J": 7, "F": 8, "D": 9, "Z": 10, "C": 11, "V": 12}

    # 名称常量
    JAVA = "Ljava"

    # 初始化方法常量
    INIT = "<init>"
    CINIT = "<clinit>"

    # 文件类型常量
    LIB = "lib"
    APP = "apk"
    RESOURCE = "R$"

    # 是否包含常量
    YES = 1
    NO = 0

    #


