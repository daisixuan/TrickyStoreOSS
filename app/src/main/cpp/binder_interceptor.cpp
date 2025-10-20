// Copyright 2025 Dakkshesh <beakthoven@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <android/binder.h>
#include <binder/Binder.h>
#include <binder/Common.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <sys/ioctl.h>
#include <utils/StrongPointer.h>

#include <map>
#include <memory>
#include <queue>
#include <shared_mutex>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "logging.hpp"
#include "lsplt.hpp"

using namespace android;

namespace {
namespace intercept_constants {
constexpr uint32_t kRegisterInterceptor = 1;
constexpr uint32_t kUnregisterInterceptor = 2;

constexpr uint32_t kPreTransact = 1;
constexpr uint32_t kPostTransact = 2;

constexpr uint32_t kActionSkip = 1;
constexpr uint32_t kActionContinue = 2;
constexpr uint32_t kActionOverrideReply = 3;
constexpr uint32_t kActionOverrideData = 4;

constexpr uint32_t kBackdoorCode = 0xdeadbeef;
} // namespace intercept_constants
} // namespace

class BinderInterceptor : public BBinder {
    struct InterceptorRegistration {
        wp<IBinder> target_binder{};
        sp<IBinder> interceptor_binder;

        InterceptorRegistration() = default;
        InterceptorRegistration(wp<IBinder> target, sp<IBinder> interceptor)
            : target_binder(std::move(target)), interceptor_binder(std::move(interceptor)) {}
    };
    using RwLock = std::shared_mutex;
    // 当一个线程持有 WriteGuard 时，其他任何线程（无论是请求 WriteGuard 还是 ReadGuard）都将被阻塞，直到写锁被释放
    using WriteGuard = std::unique_lock<RwLock>;
    // 当一个线程持有 ReadGuard 时，其他请求 ReadGuard 的线程可以同时获得锁并访问共享资源（即多个线程可以同时读取）。但是，任何请求 WriteGuard 的线程都会被阻塞
    using ReadGuard = std::shared_lock<RwLock>;

    mutable RwLock interceptor_registry_lock_;
    std::map<wp<IBinder>, InterceptorRegistration> interceptor_registry_{};

public:
    status_t onTransact(uint32_t code, const android::Parcel &data, android::Parcel *reply, uint32_t flags) override;

    bool handleInterceptedTransaction(sp<BBinder> target_binder, uint32_t transaction_code, const Parcel &request_data,
                                      Parcel *reply_data, uint32_t transaction_flags, status_t &result);

    bool shouldInterceptBinder(const wp<BBinder> &target_binder) const;

private:
    status_t handleRegisterInterceptor(const android::Parcel &data);
    status_t handleUnregisterInterceptor(const android::Parcel &data);

    template <typename ParcelWriter>
    status_t writeInterceptorCallData(ParcelWriter &writer, sp<BBinder> target_binder, uint32_t transaction_code,
                                      uint32_t transaction_flags, const Parcel &data) const;

    status_t validateInterceptorResponse(const Parcel &response, int32_t &action_type) const;
};

static sp<BinderInterceptor> g_binder_interceptor = nullptr;

struct ThreadTransactionInfo {
    uint32_t transaction_code;
    wp<BBinder> target_binder;

    ThreadTransactionInfo() = default;
    ThreadTransactionInfo(uint32_t code, wp<BBinder> target) : transaction_code(code), target_binder(std::move(target)) {}
};

thread_local std::queue<ThreadTransactionInfo> g_thread_transaction_queue;

class BinderStub : public BBinder {
    status_t onTransact(uint32_t code, const android::Parcel &data, android::Parcel *reply, uint32_t flags) override {
        LOGD("BinderStub transaction: %u", code);

        if (g_thread_transaction_queue.empty()) {
            LOGW("No pending transaction info for stub");
            return UNKNOWN_TRANSACTION;
        }
        // 从队列中恢复原始信息
        auto transaction_info = g_thread_transaction_queue.front();
        g_thread_transaction_queue.pop();

        if (transaction_info.target_binder == nullptr && transaction_info.transaction_code == intercept_constants::kBackdoorCode &&
            reply != nullptr) {
            // java层请求的getBinderBackdoor
            LOGD("Backdoor access requested - providing interceptor reference");
            reply->writeStrongBinder(g_binder_interceptor);
            return OK;
        }
        // 返回的是原始 Keystore 服务的 Binder 对象 尝试将弱引用转换为强引用
        if (auto promoted_target = transaction_info.target_binder.promote()) {
            LOGD("Processing intercepted transaction");
            status_t result;
            if (!g_binder_interceptor->handleInterceptedTransaction(promoted_target, transaction_info.transaction_code, data, reply,
                                                                    flags, result)) {
                LOGD("Forwarding to original binder");
                result = promoted_target->transact(transaction_info.transaction_code, data, reply, flags);
            }
            return result;
        } else {
            LOGE("Failed to promote weak reference to target binder");
            return DEAD_OBJECT;
        }
    }
};

static sp<BinderStub> g_binder_stub = nullptr;

int (*original_ioctl_function)(int fd, int request, ...) = nullptr;

namespace {
bool processBinderTransaction(binder_transaction_data *transaction_data) {
    // 验证事务数据的有效性 如果事务数据为空或目标指针无效,直接返回 false 表示不拦截。
    if (!transaction_data || transaction_data->target.ptr == 0) {
        return false;
    }

    bool should_intercept = false;
    ThreadTransactionInfo transaction_info{};
    // 检查是否为特殊的 backdoor 访问请求
    // 发送者 UID 为 0 (root): 确保只有特权进程能访问 backdoor
    if (transaction_data->code == intercept_constants::kBackdoorCode && transaction_data->sender_euid == 0) {
        transaction_info.transaction_code = intercept_constants::kBackdoorCode;
        transaction_info.target_binder = nullptr;
        should_intercept = true;
        LOGD("Backdoor transaction detected from root user");
    } else {
        // 对于非 backdoor 的普通事务
        // 获取目标 Binder 对象 从 transaction_data->target.ptr 获取弱引用
        auto *weak_ref = reinterpret_cast<RefBase::weakref_type *>(transaction_data->target.ptr);
        if (weak_ref->attemptIncStrong(nullptr)) {
            // 从 cookie 字段获取实际的 BBinder 指针
            auto *target_binder = reinterpret_cast<BBinder *>(transaction_data->cookie);
            auto weak_binder = wp<BBinder>::fromExisting(target_binder);
            // 检查该 Binder 是否已注册拦截器
            if (g_binder_interceptor->shouldInterceptBinder(weak_binder)) {
                // 如果需要拦截,保存原始事务信息到 ThreadTransactionInfo 结构体 在onTransact处理后需要恢复
                transaction_info.transaction_code = transaction_data->code;
                transaction_info.target_binder = weak_binder;
                should_intercept = true;
                LOGD("Interception required for transaction code=%u target=%p", transaction_data->code, target_binder);
            }
            target_binder->decStrong(nullptr);
        }
    }

    if (should_intercept) {
        LOGD("Redirecting transaction through stub");
        // 将事务的目标从原始 Keystore 服务改为 g_binder_stub
        // target.ptr: 指向 stub 的弱引用
        // cookie: 指向 stub 对象本身
        // code: 改为 backdoor 魔术数字,让 stub 知道这是被拦截的事务
        transaction_data->target.ptr = reinterpret_cast<uintptr_t>(g_binder_stub->getWeakRefs());
        transaction_data->cookie = reinterpret_cast<uintptr_t>(g_binder_stub.get());
        transaction_data->code = intercept_constants::kBackdoorCode;
        // 将原始事务信息推入线程本地队列,供后续 BinderStub::onTransact 使用
        g_thread_transaction_queue.push(std::move(transaction_info));
    }

    return should_intercept;
}

void processBinderWriteRead(const binder_write_read &write_read_data) {
    if (write_read_data.read_buffer == 0 || write_read_data.read_size == 0 || write_read_data.read_consumed <= sizeof(uint32_t)) {
        return;
    }

    LOGD("Processing binder read buffer: ptr=%p size=%zu consumed=%zu", reinterpret_cast<void *>(write_read_data.read_buffer),
         write_read_data.read_size, write_read_data.read_consumed);

    auto buffer_ptr = write_read_data.read_buffer;
    auto remaining_bytes = write_read_data.read_consumed;

    while (remaining_bytes > 0) {
        if (remaining_bytes < sizeof(uint32_t)) {
            LOGE("Insufficient bytes for command header: %llu", static_cast<unsigned long long>(remaining_bytes));
            break;
        }

        auto command = *reinterpret_cast<const uint32_t *>(buffer_ptr);
        buffer_ptr += sizeof(uint32_t);
        remaining_bytes -= sizeof(uint32_t);

        auto command_size = _IOC_SIZE(command);
        LOGD("Processing binder command: %u (size: %u)", command, command_size);

        if (remaining_bytes < command_size) {
            LOGE("Insufficient bytes for command data: %llu < %u", static_cast<unsigned long long>(remaining_bytes), command_size);
            break;
        }

        if (command == BR_TRANSACTION_SEC_CTX || command == BR_TRANSACTION) {
            binder_transaction_data *transaction_data = nullptr;
            // 处理BR_TRANSACTION_SEC_CTX 包含安全上下文的事务 和BR_TRANSACTION 标准 Binder 事务
            // 获取他的transaction_data
            if (command == BR_TRANSACTION_SEC_CTX) {
                LOGD("Processing BR_TRANSACTION_SEC_CTX");
                auto *secctx_data = reinterpret_cast<const binder_transaction_data_secctx *>(buffer_ptr);
                transaction_data = const_cast<binder_transaction_data *>(&secctx_data->transaction_data);
            } else {
                LOGD("Processing BR_TRANSACTION");
                transaction_data = reinterpret_cast<binder_transaction_data *>(buffer_ptr);
            }

            if (transaction_data) {
                // 识别到事务后,调用 processBinderTransaction 进行实际的拦截处理
                processBinderTransaction(transaction_data);
            } else {
                LOGE("Failed to extract transaction data");
            }
        }

        buffer_ptr += command_size;
        remaining_bytes -= command_size;
    }
}
} // namespace

int intercepted_ioctl_function(int fd, int request, ...) {
    va_list args;
    va_start(args, request);
    auto *argument = va_arg(args, void *);
    va_end(args);

    auto result = original_ioctl_function(fd, request, argument);

    if (result >= 0 && request == BINDER_WRITE_READ && argument) {
        // 处理Binder读写请求
        const auto &write_read_data = *static_cast<const binder_write_read *>(argument);
        processBinderWriteRead(write_read_data);
    }

    return result;
}

bool BinderInterceptor::shouldInterceptBinder(const wp<BBinder> &target_binder) const {
    ReadGuard guard{interceptor_registry_lock_};
    return interceptor_registry_.find(target_binder) != interceptor_registry_.end();
}

status_t BinderInterceptor::onTransact(uint32_t code, const android::Parcel &data, android::Parcel *reply, uint32_t flags) {
    switch (code) {
    case intercept_constants::kRegisterInterceptor:
        return handleRegisterInterceptor(data);
    case intercept_constants::kUnregisterInterceptor:
        return handleUnregisterInterceptor(data);
    default:
        return UNKNOWN_TRANSACTION;
    }
}

status_t BinderInterceptor::handleRegisterInterceptor(const android::Parcel &data) {
    sp<IBinder> target_binder, interceptor_binder;

    if (data.readStrongBinder(&target_binder) != OK) {
        LOGE("Failed to read target binder from registration data");
        return BAD_VALUE;
    }

    if (!target_binder->localBinder()) {
        LOGE("Target binder is not a local binder");
        return BAD_VALUE;
    }

    if (data.readStrongBinder(&interceptor_binder) != OK) {
        LOGE("Failed to read interceptor binder from registration data");
        return BAD_VALUE;
    }

    {
        WriteGuard write_guard{interceptor_registry_lock_};
        wp<IBinder> weak_target = target_binder;

        auto iterator = interceptor_registry_.lower_bound(weak_target);
        if (iterator == interceptor_registry_.end() || iterator->first != weak_target) {
            iterator =
                interceptor_registry_.emplace_hint(iterator, weak_target, InterceptorRegistration{weak_target, interceptor_binder});
        } else {
            iterator->second.interceptor_binder = interceptor_binder;
        }

        LOGI("Registered interceptor for binder %p", target_binder.get());
        return OK;
    }
}

status_t BinderInterceptor::handleUnregisterInterceptor(const android::Parcel &data) {
    sp<IBinder> target_binder, interceptor_binder;

    if (data.readStrongBinder(&target_binder) != OK) {
        LOGE("Failed to read target binder from unregistration data");
        return BAD_VALUE;
    }

    if (!target_binder->localBinder()) {
        LOGE("Target binder is not a local binder");
        return BAD_VALUE;
    }

    if (data.readStrongBinder(&interceptor_binder) != OK) {
        LOGE("Failed to read interceptor binder from unregistration data");
        return BAD_VALUE;
    }

    {
        WriteGuard write_guard{interceptor_registry_lock_};
        wp<IBinder> weak_target = target_binder;

        auto iterator = interceptor_registry_.find(weak_target);
        if (iterator != interceptor_registry_.end()) {
            if (iterator->second.interceptor_binder != interceptor_binder) {
                LOGE("Interceptor mismatch during unregistration");
                return BAD_VALUE;
            }
            interceptor_registry_.erase(iterator);
            LOGI("Unregistered interceptor for binder %p", target_binder.get());
            return OK;
        }

        LOGW("Attempted to unregister non-existent interceptor");
        return BAD_VALUE;
    }
}
// target_binder: 原始的目标 Keystore Binder 对象
// transaction_code: 原始事务码(如 generateKey)
// request_data: 请求数据的 Parcel
// reply_data: 响应数据的 Parcel 指针
// transaction_flags: 事务标志
// result: 输出参数,存储事务执行结果
bool BinderInterceptor::handleInterceptedTransaction(sp<BBinder> target_binder, uint32_t transaction_code, const Parcel &request_data,
                                                     Parcel *reply_data, uint32_t transaction_flags, status_t &result) {
// 在单行代码中实现错误检查、日志记录和函数退出
#define VALIDATE_STATUS(expr)                                   \
    do {                                                        \
        auto __result = (expr);                                 \
        if (__result != OK) {                                   \
            LOGE("Operation failed: " #expr " = %d", __result); \
            return false;                                       \
        }                                                       \
    } while (0)

    sp<IBinder> interceptor_binder;
    {
        // 函数首先从注册表中查找对应的 Java 层拦截器
        ReadGuard read_guard{interceptor_registry_lock_};
        auto iterator = interceptor_registry_.find(target_binder);
        if (iterator == interceptor_registry_.end()) {
            LOGE("No interceptor found for target binder %p", target_binder.get());
            return false;
        }
        interceptor_binder = iterator->second.interceptor_binder;
    }

    LOGD("Intercepting transaction: binder=%p code=%u flags=%u reply=%s", target_binder.get(), transaction_code, transaction_flags,
         reply_data ? "true" : "false");

    Parcel pre_request_data, pre_response_data, modified_request_data;
    // 使用 writeInterceptorCallData 将事务信息打包写入pre_request_data
    VALIDATE_STATUS(writeInterceptorCallData(pre_request_data, target_binder, transaction_code, transaction_flags, request_data));
    // 通过 Binder IPC 调用 Java 层的 Interceptor 的 handlePreTransact 方法
    VALIDATE_STATUS(interceptor_binder->transact(intercept_constants::kPreTransact, pre_request_data, &pre_response_data));

    int32_t pre_action_type;
    // 从响应中读取动作类型 只要是跳过、覆盖回复、覆盖数据、继续执行，则返回 true
    VALIDATE_STATUS(validateInterceptorResponse(pre_response_data, pre_action_type));

    LOGD("Pre-transaction action type: %d", pre_action_type);

    switch (pre_action_type) {
        // 不执行原始事务 结束
    case intercept_constants::kActionSkip:
        return false;

    case intercept_constants::kActionOverrideReply:
        // 读取自定义响应直接返回给应用
        result = pre_response_data.readInt32();
        if (reply_data) {
            size_t reply_size = pre_response_data.readUint64();
            VALIDATE_STATUS(reply_data->appendFrom(&pre_response_data, pre_response_data.dataPosition(), reply_size));
        }
        return true;

    case intercept_constants::kActionOverrideData: {
        // 读取修改后的请求数据 继续执行事务
        size_t data_size = pre_response_data.readUint64();
        VALIDATE_STATUS(modified_request_data.appendFrom(&pre_response_data, pre_response_data.dataPosition(), data_size));
        break;
    }

    case intercept_constants::kActionContinue:
        // 使用原始请求数据继续执行原始事务
    default:
        VALIDATE_STATUS(modified_request_data.appendFrom(&request_data, 0, request_data.dataSize()));
        break;
    }
    // 如果需要执行原始事务,调用目标 Binder 的 transact 方法
    result = target_binder->transact(transaction_code, modified_request_data, reply_data, transaction_flags);

    Parcel post_request_data, post_response_data;

    VALIDATE_STATUS(post_request_data.writeStrongBinder(target_binder));
    VALIDATE_STATUS(post_request_data.writeUint32(transaction_code));
    VALIDATE_STATUS(post_request_data.writeUint32(transaction_flags));
    VALIDATE_STATUS(post_request_data.writeInt32(IPCThreadState::self()->getCallingUid()));
    VALIDATE_STATUS(post_request_data.writeInt32(IPCThreadState::self()->getCallingPid()));
    VALIDATE_STATUS(post_request_data.writeInt32(result));
    VALIDATE_STATUS(post_request_data.writeUint64(request_data.dataSize()));
    VALIDATE_STATUS(post_request_data.appendFrom(&request_data, 0, request_data.dataSize()));

    size_t reply_size = reply_data ? reply_data->dataSize() : 0;
    VALIDATE_STATUS(post_request_data.writeUint64(reply_size));
    LOGD("Transaction sizes: request=%zu reply=%zu", request_data.dataSize(), reply_size);

    if (reply_data && reply_size > 0) {
        VALIDATE_STATUS(post_request_data.appendFrom(reply_data, 0, reply_size));
    }
    // 事务执行完成后,调用 Java 层拦截器的 handlePostTransact 方法
    VALIDATE_STATUS(interceptor_binder->transact(intercept_constants::kPostTransact, post_request_data, &post_response_data));

    int32_t post_action_type;
    // 从响应中读取动作类型 只要是跳过、覆盖回复、覆盖数据、继续执行，则返回 true
    VALIDATE_STATUS(validateInterceptorResponse(post_response_data, post_action_type));

    LOGD("Post-transaction action type: %d", post_action_type);

    if (post_action_type == intercept_constants::kActionOverrideReply) {
        result = post_response_data.readInt32();
        if (reply_data) {
            size_t new_reply_size = post_response_data.readUint64();
            reply_data->freeData();
            VALIDATE_STATUS(reply_data->appendFrom(&post_response_data, post_response_data.dataPosition(), new_reply_size));
            LOGD("Reply overridden: original_size=%zu new_size=%zu", reply_size, new_reply_size);
        }
    }

    return true;

#undef VALIDATE_STATUS
}

template <typename ParcelWriter>
status_t BinderInterceptor::writeInterceptorCallData(ParcelWriter &writer, sp<BBinder> target_binder, uint32_t transaction_code,
                                                     uint32_t transaction_flags, const Parcel &data) const {
    auto status = writer.writeStrongBinder(target_binder);
    if (status != OK)
        return status;

    status = writer.writeUint32(transaction_code);
    if (status != OK)
        return status;

    status = writer.writeUint32(transaction_flags);
    if (status != OK)
        return status;

    status = writer.writeInt32(IPCThreadState::self()->getCallingUid());
    if (status != OK)
        return status;

    status = writer.writeInt32(IPCThreadState::self()->getCallingPid());
    if (status != OK)
        return status;

    status = writer.writeUint64(data.dataSize());
    if (status != OK)
        return status;

    return writer.appendFrom(&data, 0, data.dataSize());
}

status_t BinderInterceptor::validateInterceptorResponse(const Parcel &response, int32_t &action_type) const {
    auto status = response.readInt32(&action_type);
    if (status != OK) {
        LOGE("Failed to read action type from interceptor response");
        return status;
    }

    switch (action_type) {
    case intercept_constants::kActionSkip:
    case intercept_constants::kActionContinue:
    case intercept_constants::kActionOverrideReply:
    case intercept_constants::kActionOverrideData:
        return OK;
    default:
        LOGE("Invalid action type from interceptor: %d", action_type);
        return BAD_VALUE;
    }
}

namespace {
constexpr std::string_view kBinderLibraryName = "/libbinder.so";
constexpr std::string_view kIoctlFunctionName = "ioctl";
} // namespace

bool initializeBinderInterception() {
    auto memory_maps = lsplt::MapInfo::Scan();

    dev_t binder_device_id;
    ino_t binder_inode;
    bool binder_library_found = false;

    for (const auto &memory_map : memory_maps) {
        if (memory_map.path.ends_with(kBinderLibraryName)) {
            //找到 libbinder.so 获取其中的dev和inode 给后续lsp::RegisterHook使用
            binder_device_id = memory_map.dev;
            binder_inode = memory_map.inode;
            binder_library_found = true;
            LOGD("Found binder library: %s (dev=0x%lx, inode=%lu)", memory_map.path.c_str(),
                 static_cast<unsigned long>(binder_device_id), static_cast<unsigned long>(binder_inode));
            break;
        }
    }

    if (!binder_library_found) {
        LOGE("Failed to locate libbinder.so in process memory maps");
        return false;
    }

    g_binder_interceptor = sp<BinderInterceptor>::make();
    g_binder_stub = sp<BinderStub>::make();

    if (!g_binder_interceptor || !g_binder_stub) {
        LOGE("Failed to create binder interceptor components");
        return false;
    }
    // hook binder中的 ioctl
    // 无论文件被软链接到哪里、被挂载到哪里，或者进程在内存中如何映射它，文件的 (设备 ID, 索引节点号) 组合始终保持不变
    lsplt::RegisterHook(binder_device_id, binder_inode, kIoctlFunctionName.data(),
                        reinterpret_cast<void *>(intercepted_ioctl_function), reinterpret_cast<void **>(&original_ioctl_function));

    if (!lsplt::CommitHook()) {
        LOGE("Failed to commit binder ioctl hook");
        g_binder_interceptor.clear();
        g_binder_stub.clear();
        return false;
    }

    LOGI("Binder interception initialized successfully");
    return true;
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
bool entry(void *library_handle) {
    LOGI("TrickyStore binder interceptor loaded (handle: %p)", library_handle);
    // 此时已经注入到目标进程中
    bool success = initializeBinderInterception();
    if (success) {
        LOGI("Binder interception entry point completed successfully");
    } else {
        LOGE("Binder interception initialization failed");
    }

    return success;
}
