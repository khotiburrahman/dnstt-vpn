package com.example.dnsttvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import mobile.Mobile
import mobile.SocketProtector
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class VpnTunnelService : VpnService(), SocketProtector {

    companion object {
        const val ACTION_CONNECT = "com.example.dnsttvpn.CONNECT"
        const val ACTION_DISCONNECT = "com.example.dnsttvpn.DISCONNECT"
        const val ACTION_STATUS_CHANGED = "com.example.dnsttvpn.STATUS_CHANGED"
        const val EXTRA_DOH_URL = "doh_url"
        const val EXTRA_DOMAIN = "domain"
        const val EXTRA_PUB_KEY = "pub_key"
        const val EXTRA_SSH_USER = "ssh_user"
        const val EXTRA_SSH_PASS = "ssh_pass"
        const val EXTRA_SSH_HOST = "ssh_host"
        const val EXTRA_SSH_PORT = "ssh_port"
        const val EXTRA_STATUS = "status"

        private const val CHANNEL_ID = "dnstt_vpn_channel"
        private const val NOTIFICATION_ID = 101

        val isRunning = AtomicBoolean(false)
    }

    private val executor = Executors.newSingleThreadExecutor()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopTunnel(stopServiceAfter = true)
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val dohUrl = intent.getStringExtra(EXTRA_DOH_URL).orEmpty()
                val domain = intent.getStringExtra(EXTRA_DOMAIN).orEmpty()
                val pubKey = intent.getStringExtra(EXTRA_PUB_KEY).orEmpty()
                val sshUser = intent.getStringExtra(EXTRA_SSH_USER).orEmpty()
                val sshPass = intent.getStringExtra(EXTRA_SSH_PASS).orEmpty()
                val sshHost = intent.getStringExtra(EXTRA_SSH_HOST).orEmpty().ifEmpty { "127.0.0.1" }
                val sshPort = intent.getIntExtra(EXTRA_SSH_PORT, 22)

                startForegroundServiceNotification()
                broadcastStatus("Connecting...")
                executor.execute {
                    startTunnel(dohUrl, domain, pubKey, sshHost, sshPort, sshUser, sshPass)
                }
            }
        }
        return START_STICKY
    }

    private fun startForegroundServiceNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "DNSTT VPN Service", NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        else PendingIntent.FLAG_UPDATE_CURRENT

        val openAppIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), flags
        )
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("DNSTT VPN Aktif")
            .setContentText("Tunnel SSH via DNS")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openAppIntent)
            .setOngoing(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()

        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, fgsType)
    }

    private fun startTunnel(
        dohUrl: String, domain: String, pubKey: String,
        sshHost: String, sshPort: Int, sshUser: String, sshPass: String
    ) {
        if (isRunning.get()) {
            try { Mobile.stopTunnel() } catch (_: Exception) {}
            isRunning.set(false)
        }

        val builder = Builder()
            .setSession("DNSTT VPN")
            .setMtu(1500)
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDisallowedApplication(packageName)

        val pfd = builder.establish() ?: run {
            broadcastStatus("Gagal membuat interface TUN")
            stopTunnel(stopServiceAfter = true)
            return
        }

        val rawTunFd = pfd.detachFd()
        try {
            Mobile.startTunnel(
                rawTunFd.toLong(), dohUrl, pubKey, domain,
                sshHost, sshPort.toLong(), sshUser, sshPass, this
            )
            isRunning.set(true)
            broadcastStatus("Connected")
        } catch (e: Exception) {
            isRunning.set(false)
            broadcastStatus("Gagal: ${e.message ?: "tidak diketahui"}")
            stopTunnel(stopServiceAfter = true)
        }
    }

    private fun stopTunnel(stopServiceAfter: Boolean) {
        executor.execute {
            if (isRunning.getAndSet(false)) {
                try { Mobile.stopTunnel() } catch (_: Exception) {}
            }
            if (stopServiceAfter) {
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun broadcastStatus(status: String) {
        sendBroadcast(Intent(ACTION_STATUS_CHANGED).apply {
            setPackage(packageName)
            putExtra(EXTRA_STATUS, status)
        })
    }

    override fun protectFd(fd: Long): Boolean = protect(fd.toInt())

    override fun onRevoke() {
        stopTunnel(stopServiceAfter = true)
        super.onRevoke()
    }

    override fun onDestroy() {
        if (isRunning.getAndSet(false)) {
            try { Mobile.stopTunnel() } catch (_: Exception) {}
        }
        executor.shutdown()
        super.onDestroy()
    }
}