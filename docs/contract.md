# 有界目标数据重定位

这是调用方给定section/symbol记录的离线链接数据API，不解析或执行ELF/PE/机器代码。sections为1..100个唯一name/base/size，base整数0..1000000、size1..100000，地址半开区间不得相交。symbols为0..1000项唯一name、既有section、offset在段内、global严格bool；global只是保留声明，不改变可见性解析，符号名全局唯一，不支持弱符号。

relocations为0..2000项唯一id、既有section/symbol、offset、addend整数±1000000、width1..8字节，目标写区间必须完全在段内且同段各重定位不得重叠。值为section(symbol).base+symbol.offset+addend，必须在[0,2^(8*width))，否则整体拒绝；输出小端字节数组，负值不作补码截断。输入顺序保留，无PC相对重定位或实际二进制修改。

样例msg地址8194，2字节为[2,32]。不是代码片段管理、批量文件工具或依赖安装项目。后续多对象符号解析和不同重定位类型可沿section/symbol/relocation身份接入；当前不承诺任何真实对象格式兼容。普通字段/整数拒绝bool及未知字段。IO原子新建，拒绝已有路径及链接。
