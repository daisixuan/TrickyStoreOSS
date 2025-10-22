# 模块运行流程

## 1.安装脚本 customize.sh
- 1.1 判断环境
  - 判断root管理器环境和机器环境(arm or x86/32位 or 64位)
- 1.2 对脚本进行主动解压到模块目录下
  - customize.sh module.prop post-fs-data.sh service.sh sepolicy.rule daemon classes.dex libTrickyStoreOSS.so libinject.so
  - 1.2.1 给daemon脚本 755权限
    - 这个脚本功能是使用系统的app_process 工具启动classes.dex 指定程序名字为TrickyStoreOSS 运行主类是io.github.beakthoven.TrickyStoreOSS.MainKt
  - 1.2.2 将libinject.so改为inject可执行文件
  - 1.2.3 如果没有配置文件夹则创建配置文件夹和文件
    - /data/adb/tricky_store/keybox.xml
    - /data/adb/tricky_store/target.txt

## 2.设置sepolicy权限

```
sepolicy.rule
# 允许 keystore 服务访问系统文件（Unix Domain Socket）
allow keystore system_file unix_dgram_socket *
# 允许系统文件访问 keystore 服务（Unix Domain Socket）
allow system_file keystore unix_dgram_socket *
# 允许 keystore 访问系统文件（通用文件权限）
allow keystore system_file file *
# 允许 crash_dump 访问 keystore (进程权限)
allow crash_dump keystore process *
```

## 3.启动脚本 service.sh

- 循环启动daemon脚本 确保成功


## 4.java启动流程

- ### 4.1 AndroidUtils.setupBootHash
  - #### 4.1.1 getBootHashFromProp 
    - 获取系统属性ro.boot.vbmeta.digest
    - 如果成功获取则结束 不成功进入4.1.2
  - #### 4.1.2 getBootHashFromAttestation
    - 获取手机原始的KeyStore证书链的verifiedBootHash
      - 如果tee不支持则返回空
    - 如果成功则把这个值设置到ro.boot.vbmeta.digest结束
    - 失败则进入4.1.3
  - #### 4.1.3 randomBytes
    - 随机生成一串长度64的hex字符串设置到ro.boot.vbmeta.digest
- ### 4.2 initializeInterceptors
  - #### 4.2.1 selectKeystoreInterceptor
    - 选择KeyStore的拦截器
      - android 10 和 11 使用 KeystoreInterceptor
      - android 12及其以上使用 Keystore2Interceptor
  - #### 4.2.2 interceptor.tryRunKeystoreInterceptor
    - 获取ServiceManager.getService("android.system.keystore2.IKeystoreService/default")这个服务
    - 尝试使用0xdeadbeef这个事务码获取backdoor的Binder对象这个是libTrickyStoreOSS中构造的第一次进入还没有加载这个so所以会走handleMissingBackdoor
    - #### 4.2.2.1 handleMissingBackdoor
      - 尝试handleMissingBackdoor超过3次就退出程序
      - /system/bin/sh -c "exec ./inject `pidof keystore2` libTrickyStoreOSS.so entry" 返回0就是成功
      - 执行这个命令此时就进入inject流程
    - #### 4.2.2.2 setupInterceptor
      - 见 7.Java流程 拦截器注册
  - #### 4.2.3 PkgConfig.initialize()
    - 加载用户配置
      - 需要hook的app
      - 自定义的keybox
      - 检测tee状态是否损坏
        - 损坏了自动模式就走生成
        - 否则走修改
      - security_patch是否修改
      - 
- ### 4.3 maintainService
  - 阻塞主线程 让程序不要退出


## 5.native inject流程 app/src/main/cpp/inject/main.cpp
  - 主要逻辑为inject::inject_library
    - 入参
      - keystore程序的pid 
      - 注入so libTrickyStoreOSS.so
      - 执行so方法入口函数 entry
  - 5.1 ptrace attach keystore程序
  - 5.2 获取当前寄存器并备份
  - 5.3 使用lsplt框架的 lsplt::MapInfo::Scan 获取当前进程的map和keystore的map
  - 5.4 使用 **find_module_return_addr** 函数找到libc.so在keystore的map中的起始地址
    - 通过keystore的map
  - 5.5 使用 **transfer_fd_to_remote** 函数 打开libTrickyStoreOSS.so 拿到fd给后续的android_dlopen_ext使用
    - 通过 Unix socket 传输文件描述符的方式
    - 在不需要远程进程自己打开文件的情况下,将已打开的文件描述符传递给目标进程,这对于注入场景特别有用,因为目标进程可能没有权限直接访问注入库文件
    - 实现比较复杂需要配合**find_func_addr**和**remote_call**来实现
    - find_func_addr
      - 入参
        - 当前进程的map
        - 注入进程的map
        - 函数所在的模块(so)名字
        - 需要查找的函数名
      - 在当前进程使用dlopen打开模块 获取lib_handle
      - 使用dlsym找到函数名在当前进程的符号地址 symbol_addr
      - find_module_base
        - 获取模块在map中的基址
      - 找到当前进程和注入进程的模块基址
      - 通过symbol_addr减去当前进程的模块基址得到偏移 symbol_offset
      - 通过注入进程的模块基址+symbol_offset得到注入模块的函数地址返回
    - remote_call
      - remote_pre_call 实现调用 在目标进程写入PC、参数和返回地址
        - 入参
          - pid
          - 寄存器
          - 函数地址
          - 自定义返回地址
          - 函数调用参数
        - align_stack
          - 栈对齐
        - write_proc
          - 2种模式写入数据
            - 通过 /proc/[pid]/mem 文件写入
              - 打开 /proc/[pid]/mem 文件
              - 使用 pwrite 系统调用在指定偏移量写入数据
            - 使用 process_vm_writev 系统调用
              - 构造本地和远程的 iovec 结构体
              - 调用 process_vm_writev 直接写入目标进程内存
        - 设置x30寄存器为自定义返回地址
        - 设置pc为函数地址
        - set_regs
          - ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &reg_iov)
            - 使用ptrace设置寄存器
        - ptrace(PTRACE_CONT, pid, 0, 0)
          - 恢复目标执行 并且不向它发送任何信号
          - 将一个被跟踪且当前处于暂停状态的进程从暂停中释放，使其能够继续运行其代码
      - remote_post_call 实现获取返回值
        - 等待函数执行完成
          - 调用 wait_for_trace 等待远程进程停止
        - 读取寄存器状态
          - 使用 get_regs 获取远程进程当前的寄存器状态,这些寄存器中包含了函数的返回值
        - 验证返回地址
          - 函数检查停止信号是否为 SIGSEGV,并验证程序计数器(IP寄存器)是否指向预期的返回地址。如果返回地址不匹配,说明函数执行出现异常,会记录崩溃详情并返回0
        - 提取返回值
          - 关键步骤:从 REG_RET(x0) 寄存器中读取返回值

  - 5.6 使用**remote_dlopen**函数打开 libTrickyStoreOSS.so 拿到handle_opt
    - 使用find_func_addr拿到libc.so中的android_dlopen_ext地址
    - 这里还使用了push_memory和push_string把参数传入目标进程
      - push_memory 函数使用它将数据推送到远程进程的栈上
      - push_string 函数使用它将字符串写入远程栈
    - 使用remote_call调用android_dlopen_ext("libTrickyStoreOSS.so", RTLD_NOW, dlext_info)
      - dlext_info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
      - dlext_info.library_fd = lib_fd;
      - 表示使用fd打开这个so fd就是transfer_fd_to_remote获取的
    - 返回android_dlopen_ext打开so拿到的handle
    - find_func_addr+remote_call 调用 close 关闭这个fd
  - 5.7 使用**remote_find_entry**函数找到入口函数 **entry** 地址
    - 在目标进程中使用dlsym寻找entry地址
  - 5.8 使用**remote_call_entry**函数调用**entry** 函数
    - 使用remote_call调用entry


## 6.native流程 libTrickyStoreOSS.so 流程 app/src/main/cpp/binder_interceptor.cpp
  - 6.1 entry函数入口
    - 调用initializeBinderInterception
  - 6.2 initializeBinderInterception
    - 使用lsplt::MapInfo::Scan获取当前map信息(此时已经注入为注入进程的map)
    - 找到 libbinder.so 获取其中的dev和inode
      - 给后续lsp::RegisterHook使用
    - 初始化BinderInterceptor和BinderStub
      - g_binder_interceptor(BinderInterceptor)
        - 这个就是backdoor
      - g_binder_stub(BinderStub)
    - 使用lsplt::RegisterHook hook libbinder.so 中的 ioctl函数替换为intercepted_ioctl_function
  - 6.3 intercepted_ioctl_function
    - 执行原始逻辑 如果返回值是 处理Binder读写请求并且有参数则进入processBinderWriteRead
  - 6.4 processBinderWriteRead
    - 解析参数后 处理BR_TRANSACTION_SEC_CTX 包含安全上下文的事务 和BR_TRANSACTION 标准 Binder 事务
    - 识别到事务后,调用 processBinderTransaction 进行实际的拦截处理
  - 6.5 processBinderTransaction
    - 检查是否为特殊的 backdoor 访问请求
      - 通过事务码0xdeadbeef和发送者 UID 为 0 (root): 确保只有特权进程能访问 backdoor
    - 对于非 backdoor 的普通事务
      - 获取目标 Binder 对象 从 transaction_data->target.ptr 获取弱引用
      - 检查该 Binder 是否已注册拦截器
      - 如果需要拦截,保存原始事务信息到 ThreadTransactionInfo 结构体 在onTransact处理后需要恢复
        - 将事务的目标从原始 Keystore 服务改为 g_binder_stub
          - target.ptr: 指向 stub 的弱引用
          - cookie: 指向 stub 对象本身
          - code: 改为 backdoor 魔术数字,让 stub 知道这是被拦截的事务 
        - 将原始事务信息推入线程本地队列 g_thread_transaction_queue,供后续 BinderStub::onTransact 使用
  - 6.6 进入BinderStub::onTransact
    - 从g_thread_transaction_queue队列中恢复原始信息
    - 如果transaction_info的请求码是0xdeadbeef
      - 返回g_binder_interceptor给java
    - 如果是其他 则调用g_binder_interceptor->handleInterceptedTransaction
      - 入参
        - target_binder: 原始的目标 Keystore Binder 对象
        - transaction_code: 原始事务码(如 generateKey)
        - request_data: 请求数据的 Parcel
        - reply_data: 响应数据的 Parcel 指针
        - transaction_flags: 事务标志
        - result: 输出参数,存储事务执行结果
      - 函数首先从注册表中查找对应的 Java 层拦截器
        - 使用 writeInterceptorCallData 将事务信息打包写入pre_request_data
        - 通过 Binder IPC 调用 Java 层的 Interceptor 的 handlePreTransact 方法
          - 从java的响应中读取动作类型
            - Skip 拦截器不处理这个事务 让事务正常执行
              - 返回false
            - OverrideReply 读取自定义响应直接返回给应用 将修改后的返回直接调用原始服务的reply_data
              - 返回true
            - createTypedObjectReply 读取修改后的请求数据 继续执行事务 后续还会经过handlePostTransact
              - 先把修改后的请求数据传给原服务 
              - target_binder->transact 调用目标 Binder 的 transact 方法
            
            - Continue 使用原始请求数据继续执行原始事务后续还会经过handlePostTransact
              - 先把原始请求数据传给原服务 
              - target_binder->transact 调用目标 Binder 的 transact 方法
        - 事务执行完成后,调用 Java 层拦截器的 handlePostTransact 方法
          - 如果是kActionOverrideReply（覆盖回复）
            - 读取新的返回码
            - 替换回复数据
            - 当拦截器需要修改密钥认证响应时
              - 拦截器在 onPostTransact() 中检测到需要修改的证书链
              - 返回 OverrideReply 结果,包含修改后的证书数据
              - 将修改后的数据写入 reply_data,替换原始系统服务的响应
                - reply_data->appendFrom
    - 如果g_binder_interceptor->handleInterceptedTransaction返回false
      - 则调用原始的binder处理


## 7.Java流程 拦截器注册
  - 7.1 setupInterceptor
    - 此时已经有了backdoor对象
    - registerBinderInterceptor(backdoor, service, this)
      - 注册KeystoreInterceptor/Keystore2Interceptor拦截器
      - data写入backdoor和原始服务的Biner对象
      - 通过backdoor.transact向native服务发送REGISTER_INTERCEPTOR_CODE事务码注册拦截器
        - 进入native的handleRegisterInterceptor函数
          - 写入interceptor_registry_ 当原始服务进入的时候会走拦截器流程
    - service.linkToDeath(createDeathRecipient(), 0)
      - 建立一个Binder死亡监听机制，来监控keystore是否死亡 死亡后直接退出程序重启进程
    - onInterceptorSetup(service, backdoor)
      - KeystoreInterceptor流程
        - 无
      - Keystore2Interceptor流程
        - 注册setupSecurityLevelInterceptors
          - ks.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)
            - 拿到tee的接口实现类
            - 构造SecurityLevelInterceptor为tee拦截器
            - registerBinderInterceptor 注册tee Binder的拦截器
          - ks.getSecurityLevel(SecurityLevel.STRONGBOX)
            - 拿到strongBox的接口实现类
            - 构造SecurityLevelInterceptor为strongBox拦截器
            - registerBinderInterceptor 注册strongBox Binder的拦截器

## 8.Java流程 源码拦截器解析
  - 8.1 Keystore2Interceptor
    - onPreTransact
      - getKeyEntry
        - 需要有keybox如果没有则执行原始服务流程
        - 验证是这个接口 android.system.keystore2.IKeystoreService
        - 读取native传来的数据 descriptor
        - 根据uid和配置判断需要Generate模式还是Hack模式
          - 读取tee状态
          - Generate
            - 配置指定了生成则Generate
            - 如果是自动模式 tee损坏了则Generate
            - SecurityLevelInterceptor.getKeyResponse
              - 返回不为空则 让native读取返回的数据 继续执行事务
                - 需要应用先生成generateKey才能getKeyEntry 主要逻辑在generateKey 这里只是把生成存好的值返回
              - 返回为空则 让native直接返回空给应用
          - Hack
            - 配置指定了Hack则Hack
            - 如果是自动模式 tee没损坏则Hack
            - SecurityLevelInterceptor.shouldSkipLeafHack
              - 返回是否需要跳过tee证书修改
                - 主要逻辑判断在generateKey
              - true则为返回生成的证书
              - false则为执行tee证书修改
            - SecurityLevelInterceptor.getKeyResponse
              - 逻辑同上
    - onPostTransact
      - deleteKey
        - 删除生成的证书
      - getKeyEntry
        - CertificateUtils.run { response.getCertificateChain() } 生成证书链
        - hackCertificateChain 篡改证书链
          - 用于修改现有的证书链以绕过 Android 硬件密钥认证。它接收一个证书链数组作为参数,提取叶证书中的 Google 硬件认证扩展,修改其中的 Root of Trust 数据,然后使用 keybox 中的私钥重新签名,最终返回修改后的证书链
          - 通过修改真实 TEE 生成的证书链中的 Root of Trust 数据,使得应用认为设备的 bootloader 是锁定状态,从而绕过硬件认证检查
        - response.putCertificateChain(newChain).getOrThrow() 放入原数据
        - 返回
  - 8.2 SecurityLevelInterceptor
    - 这个函数生成的数据会被 Keystore2Interceptor 在后续的 getKeyEntry 请求中使用
    - onPreTransact
      - generateKey
        - 根据配置决定是否生成合成证书来替代真实的 TEE 生成过程
          - KeyDescriptor: 密钥描述符,包含密钥别名等信息
          - attestationKeyDescriptor: 认证密钥描述符(可选)
          - params: 密钥参数数组
          - flags 和 entropy: 其他生成参数
        - needGenerate
          - 调用 CertificateHacker.generateKeyPair() 生成密钥对和证书链
          - 将生成的密钥对存储到 keyPairs HashMap 中
          - 使用 buildResponse() 构建完整的 KeyEntryResponse
          - 将响应存储到 keys HashMap 中
          - 返回 OverrideReply,直接响应给调用者,跳过真实的系统服务调用
        - needHack
          - 认证密钥场景 (purpose 包含 7 或使用了 attestationKeyDescriptor)
            - 生成完整的密钥对和证书链
            - 存储到 keyPairs 和 keys
            - **关键** 设置 skipLeafHacks 标志为 true,表示后续的 getKeyEntry 请求应该跳过叶证书修改
            - 返回 OverrideReply, 直接响应给调用者,跳过真实的系统服务调用
          - 非认证密钥场景
            - 清除该密钥的 skipLeafHacks 标志
            - 返回 Skip,让请求继续传递到真实的系统服务


## 总结

TrickyStoreOSS模块是一个复杂的系统级修改工具，主要用于拦截和修改Android系统中的KeyStore服务。该模块通过以下关键步骤运作：

1. **初始化阶段**：通过customize.sh脚本判断环境、解压文件、设置权限并创建必要的配置文件夹。

2. **权限配置**：通过sepolicy.rule设置必要的SELinux权限，允许KeyStore服务与系统文件交互。

3. **启动机制**：service.sh确保daemon脚本持续运行，daemon脚本又启动Java代码。

4. **核心工作原理**：
   - **注入技术**：使用ptrace将libTrickyStoreOSS.so注入到KeyStore服务进程中
   - **Binder拦截**：通过hook libbinder.so的ioctl函数拦截Binder通信
   - **两种工作模式**：
     - Generate模式：在TEE损坏情况下生成合成证书
     - Hack模式：在TEE正常情况下修改现有证书链的Root of Trust数据

5. **关键功能**：
   - 为需要硬件密钥认证的应用提供模拟证书
   - 修改证书链使应用认为设备的bootloader处于锁定状态
   - 通过backdoor机制在Java和Native层之间建立通信桥梁

这个模块展示了高级Android系统修改的多层次架构，包括Native注入、Binder通信拦截和Java层服务修改，主要目的是在不同的系统环境下绕过Android硬件密钥认证机制。