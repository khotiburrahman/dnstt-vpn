package com.example.dnsttvpn

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {

    private lateinit var etDohUrl: EditText
    private lateinit var etDomain: EditText
    private lateinit var etPubKey: EditText
    private lateinit var etSshUser: EditText
    private lateinit var etSshPass: EditText
    private lateinit var etSshHost: EditText
    private lateinit var etSshPort: EditText
    private lateinit var btnToggle: Button
    private lateinit var tvStatus: TextView

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val status = intent?.getStringExtra(VpnTunnelService.EXTRA_STATUS) ?: return
            tvStatus.text = "Status: $status"
            updateButtonState()
        }
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) startVpnService()
        else Toast.makeText(this, "Izin VPN ditolak", Toast.LENGTH_SHORT).show()
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { prepareAndStartVpn() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etDohUrl = findViewById(R.id.etDohUrl)
        etDomain = findViewById(R.id.etDomain)
        etPubKey = findViewById(R.id.etPubKey)
        etSshUser = findViewById(R.id.etSshUser)
        etSshPass = findViewById(R.id.etSshPass)
        etSshHost = findViewById(R.id.etSshHost)
        etSshPort = findViewById(R.id.etSshPort)
        btnToggle = findViewById(R.id.btnToggle)
        tvStatus = findViewById(R.id.tvStatus)

        btnToggle.setOnClickListener {
            if (VpnTunnelService.isRunning.get()) stopVpnService() else checkNotificationAndStart()
        }
    }

    override fun onStart() {
        super.onStart()
        ContextCompat.registerReceiver(
            this, statusReceiver,
            IntentFilter(VpnTunnelService.ACTION_STATUS_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
    }

    override fun onStop() {
        unregisterReceiver(statusReceiver)
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        updateButtonState()
        tvStatus.text = if (VpnTunnelService.isRunning.get()) "Status: Connected" else "Status: Disconnected"
    }

    private fun checkNotificationAndStart() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else prepareAndStartVpn()
    }

    private fun prepareAndStartVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermissionLauncher.launch(intent) else startVpnService()
    }

    private fun startVpnService() {
        val dohUrl = etDohUrl.text.toString().trim()
        val domain = etDomain.text.toString().trim()
        val pubKey = etPubKey.text.toString().trim()
        val sshUser = etSshUser.text.toString().trim()
        val sshPass = etSshPass.text.toString()
        val sshHost = etSshHost.text.toString().trim().ifEmpty { "127.0.0.1" }
        val sshPort = etSshPort.text.toString().trim().toIntOrNull() ?: 22

        if (dohUrl.isEmpty() || domain.isEmpty() || pubKey.isEmpty() ||
            sshUser.isEmpty() || sshPass.isEmpty()
        ) {
            Toast.makeText(this, "Lengkapi DoH, Domain, Key, SSH User & Password", Toast.LENGTH_SHORT).show()
            return
        }

        val intent = Intent(this, VpnTunnelService::class.java).apply {
            action = VpnTunnelService.ACTION_CONNECT
            putExtra(VpnTunnelService.EXTRA_DOH_URL, dohUrl)
            putExtra(VpnTunnelService.EXTRA_DOMAIN, domain)
            putExtra(VpnTunnelService.EXTRA_PUB_KEY, pubKey)
            putExtra(VpnTunnelService.EXTRA_SSH_USER, sshUser)
            putExtra(VpnTunnelService.EXTRA_SSH_PASS, sshPass)
            putExtra(VpnTunnelService.EXTRA_SSH_HOST, sshHost)
            putExtra(VpnTunnelService.EXTRA_SSH_PORT, sshPort)
        }
        ContextCompat.startForegroundService(this, intent)
        tvStatus.text = "Status: Connecting..."
        btnToggle.text = "Disconnect"
    }

    private fun stopVpnService() {
        val intent = Intent(this, VpnTunnelService::class.java).apply {
            action = VpnTunnelService.ACTION_DISCONNECT
        }
        startService(intent)
        tvStatus.text = "Status: Disconnected"
        btnToggle.text = "Connect"
    }

    private fun updateButtonState() {
        btnToggle.text = if (VpnTunnelService.isRunning.get()) "Disconnect" else "Connect"
    }
}