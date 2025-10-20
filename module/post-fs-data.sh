MODDIR=${0%/*}

# sepolicy.rule
# 允许 keystore 服务访问系统文件（Unix Domain Socket）
# 允许系统文件访问 keystore 服务（Unix Domain Socket）
# 允许 keystore 访问系统文件（通用文件权限）
# 允许 crash_dump 访问 keystore (进程权限)