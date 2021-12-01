

# 统一方法名表示形式
def valid_method_name(method_full_name):
    method_full_name = method_full_name.replace(" ", "")
    class_name = method_full_name[1:method_full_name.find(";")].replace("/",
                                                                        ".")  # com.google.android.gms.internal.bn.onPause()V
    other = method_full_name[method_full_name.find(";") + 1:]  #
    return class_name + "." + other