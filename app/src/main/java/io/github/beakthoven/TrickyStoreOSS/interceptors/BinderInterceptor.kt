/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import io.github.beakthoven.TrickyStoreOSS.logging.Logger

open class BinderInterceptor : Binder() {
    
    sealed class Result
    
    data object Skip : Result()
    
    data object Continue : Result()
    
    data class OverrideData(val data: Parcel) : Result()
    
    data class OverrideReply(val code: Int = 0, val reply: Parcel) : Result()

    companion object {
        private const val BACKDOOR_TRANSACTION_CODE = 0xdeadbeef.toInt()
        
        private const val REGISTER_INTERCEPTOR_CODE = 1
        
        private const val PRE_TRANSACT_CODE = 1
        private const val POST_TRANSACT_CODE = 2
        
        private const val RESULT_SKIP = 1
        private const val RESULT_CONTINUE = 2
        private const val RESULT_OVERRIDE_REPLY = 3
        private const val RESULT_OVERRIDE_DATA = 4

        // 该方法通过向目标 Binder 发送特殊的事务码 0xdeadbeef 来请求 backdoor 访问
        // 如果目标进程已经被注入了 libTrickyStoreOSS.so,它会识别这个特殊事务码并返回 backdoor Binder 对象
        fun getBinderBackdoor(binder: IBinder): IBinder? {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            
            return try {
                val success = binder.transact(BACKDOOR_TRANSACTION_CODE, data, reply, 0)
                if (success) {
                    Logger.d("Backdoor access granted for binder: $binder")
                    reply.readStrongBinder()
                } else {
                    Logger.d("Backdoor access denied for binder: $binder")
                    null
                }
            } catch (e: Exception) {
                Logger.e("Failed to access binder backdoor", e)
                null
            } finally {
                data.recycle()
                reply.recycle()
            }
        }

        fun registerBinderInterceptor(
            backdoor: IBinder, 
            target: IBinder, 
            interceptor: BinderInterceptor
        ) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            
            try {
                data.writeStrongBinder(target)
                data.writeStrongBinder(interceptor)
                backdoor.transact(REGISTER_INTERCEPTOR_CODE, data, reply, 0)
                Logger.d("Registered interceptor for target: $target")
            } catch (e: Exception) {
                Logger.e("Failed to register binder interceptor", e)
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
    }

    open fun onPreTransact(
        target: IBinder, 
        code: Int, 
        flags: Int, 
        callingUid: Int, 
        callingPid: Int, 
        data: Parcel
    ): Result = Skip
    
    open fun onPostTransact(
        target: IBinder, 
        code: Int, 
        flags: Int, 
        callingUid: Int, 
        callingPid: Int, 
        data: Parcel, 
        reply: Parcel?, 
        resultCode: Int
    ): Result = Skip
    // 负责和BinderInterceptor::handleInterceptedTransaction通信
    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        val result = when (code) {
            PRE_TRANSACT_CODE -> handlePreTransact(data)
            POST_TRANSACT_CODE -> handlePostTransact(data)
            else -> return super.onTransact(code, data, reply, flags)
        }
        
        writeResultToReply(result, reply!!)
        return true
    }
    
    private fun handlePreTransact(data: Parcel): Result {
        val target = data.readStrongBinder()
        val transactionCode = data.readInt()
        val transactionFlags = data.readInt()
        val callingUid = data.readInt()
        val callingPid = data.readInt()
        val dataSize = data.readLong()
        
        val transactionData = Parcel.obtain()
        return try {
            transactionData.appendFrom(data, data.dataPosition(), dataSize.toInt())
            transactionData.setDataPosition(0)
            onPreTransact(target, transactionCode, transactionFlags, callingUid, callingPid, transactionData)
        } finally {
            transactionData.recycle()
        }
    }
    
    private fun handlePostTransact(data: Parcel): Result {
        val target = data.readStrongBinder()
        val transactionCode = data.readInt()
        val transactionFlags = data.readInt()
        val callingUid = data.readInt()
        val callingPid = data.readInt()
        val resultCode = data.readInt()
        
        val transactionData = Parcel.obtain()
        val transactionReply = Parcel.obtain()
        
        return try {
            val dataSize = data.readLong().toInt()
            transactionData.appendFrom(data, data.dataPosition(), dataSize)
            transactionData.setDataPosition(0)
            data.setDataPosition(data.dataPosition() + dataSize)
            
            val replySize = data.readLong().toInt()
            val reply = if (replySize > 0) {
                transactionReply.appendFrom(data, data.dataPosition(), replySize)
                transactionReply.setDataPosition(0)
                transactionReply
            } else null
            
            onPostTransact(target, transactionCode, transactionFlags, callingUid, callingPid, transactionData, reply, resultCode)
        } finally {
            transactionData.recycle()
            transactionReply.recycle()
        }
    }
    
    private fun writeResultToReply(result: Result, reply: Parcel) {
        when (result) {
            Skip -> reply.writeInt(RESULT_SKIP)
            Continue -> reply.writeInt(RESULT_CONTINUE)
            is OverrideReply -> {
                reply.writeInt(RESULT_OVERRIDE_REPLY)
                reply.writeInt(result.code)
                reply.writeLong(result.reply.dataSize().toLong())
                reply.appendFrom(result.reply, 0, result.reply.dataSize())
                result.reply.recycle()
            }
            is OverrideData -> {
                reply.writeInt(RESULT_OVERRIDE_DATA)
                reply.writeLong(result.data.dataSize().toLong())
                reply.appendFrom(result.data, 0, result.data.dataSize())
                result.data.recycle()
            }
        }
    }
}