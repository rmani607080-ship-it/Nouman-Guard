package com.nouman.guard

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {
    private lateinit var statusText: TextView
    private lateinit var detailText: TextView
    private lateinit var toggleButton: Button
    private var requestedVpn = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        statusText = findViewById(R.id.statusText)
        detailText = findViewById(R.id.detailText)
        toggleButton = findViewById(R.id.toggleButton)
        requestNotificationPermission()
        toggleButton.setOnClickListener { toggleProtection() }
        updateUi(false)
    }

    private fun toggleProtection() {
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            requestedVpn = true
            startActivityForResult(prepare, REQUEST_VPN)
        } else {
            startProtection()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) {
            requestedVpn = false
            if (resultCode == RESULT_OK) startProtection()
            else updateUi(false, "VPN اجازت نہیں دی گئی۔")
        }
    }

    private fun startProtection() {
        val intent = Intent(this, NoumanVpnService::class.java)
        ContextCompat.startForegroundService(this, intent)
        updateUi(true)
    }

    private fun stopProtection() {
        startService(Intent(this, NoumanVpnService::class.java).setAction(NoumanVpnService.ACTION_STOP))
        updateUi(false)
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATION)
        }
    }

    private fun updateUi(active: Boolean, message: String? = null) {
        if (active) {
            statusText.text = "حفاظت فعال ہے"
            detailText.text = "Adult DNS filtering فعال ہے۔ PUBG اور عام apps کا traffic VPN tunnel میں نہیں جاتا۔"
            toggleButton.text = "STOP PROTECTION"
            toggleButton.setBackgroundColor(getColor(android.R.color.holo_red_dark))
        } else {
            statusText.text = message ?: "حفاظت غیر فعال ہے"
            detailText.text = "Protection شروع کرنے کے لیے نیچے بٹن دبائیں۔"
            toggleButton.text = "START PROTECTION"
            toggleButton.setBackgroundColor(getColor(android.R.color.holo_green_dark))
        }
    }

    companion object {
        private const val REQUEST_VPN = 100
        private const val REQUEST_NOTIFICATION = 101
    }
}
