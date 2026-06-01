package com.v2ray.ang.service

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import com.v2ray.android.net.LocalRelayProxy
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel

/**
 * Service to manage the local relay proxy lifecycle independently of the VPN service
 */
class LocalProxyService : Service() {

    private var relayProxy: LocalRelayProxy? = null
    private var serviceScope = CoroutineScope(Dispatchers.IO + Job())
    private val binder = LocalProxyBinder()
    private val TAG = "LocalProxyService"

    inner class LocalProxyBinder : Binder() {
        fun getService(): LocalProxyService = this@LocalProxyService
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        when (action) {
            ACTION_START_PROXY -> startProxy()
            ACTION_STOP_PROXY -> stopProxy()
        }
        return START_STICKY
    }

    private fun startProxy() {
        try {
            val selectedServerGuid = MmkvManager.getSelectServer()
            if (selectedServerGuid.isNullOrEmpty()) {
                LogUtil.w(TAG, "No server selected, cannot start proxy")
                return
            }

            val serverConfig = MmkvManager.decodeServerConfig(selectedServerGuid)
            if (serverConfig == null) {
                LogUtil.w(TAG, "Server config not found")
                return
            }

            val targetIP = serverConfig.server ?: "104.19.229.21"
            val targetPort = serverConfig.serverPort ?: 443

            relayProxy = LocalRelayProxy(
                listenPort = 40443,
                targetHost = targetIP,
                targetPort = targetPort
            )
            relayProxy?.start()

            LogUtil.i(TAG, "Local proxy service started: 127.0.0.1:40443 -> $targetIP:$targetPort")
        } catch (e: Exception) {
            LogUtil.e(TAG, "Failed to start local proxy service", e)
        }
    }

    private fun stopProxy() {
        try {
            relayProxy?.stop()
            relayProxy = null
            LogUtil.i(TAG, "Local proxy service stopped")
        } catch (e: Exception) {
            LogUtil.e(TAG, "Failed to stop local proxy service", e)
        }
    }

    override fun onDestroy() {
        stopProxy()
        serviceScope.cancel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START_PROXY = "com.v2ray.ang.action.START_PROXY"
        const val ACTION_STOP_PROXY = "com.v2ray.ang.action.STOP_PROXY"
    }
}
