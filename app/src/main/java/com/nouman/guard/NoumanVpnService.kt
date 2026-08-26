package com.nouman.guard

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

class NoumanVpnService : VpnService(), Runnable {
    private var vpnThread: Thread? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        if (running.get()) return START_STICKY
        startForegroundNotification()
        running.set(true)
        vpnThread = Thread(this, "NoumanGuardDnsVpn").also { it.start() }
        return START_STICKY
    }

    override fun run() {
        try {
            vpnInterface = Builder()
                .setSession("Nouman Guard DNS Protection")
                .setMtu(1500)
                .addAddress("10.10.0.2", 32)
                .addRoute("1.1.1.3", 32)
                .addRoute("1.0.0.3", 32)
                .addDnsServer("1.1.1.3")
                .addDnsServer("1.0.0.3")
                .establish() ?: return

            FileInputStream(vpnInterface!!.fileDescriptor).use { input ->
                FileOutputStream(vpnInterface!!.fileDescriptor).use { output ->
                    val buffer = ByteArray(32767)
                    while (running.get()) {
                        val length = input.read(buffer)
                        if (length <= 0) continue
                        val packet = buffer.copyOf(length)
                        val query = DnsPacketEngine.parseQuery(packet, length) ?: continue
                        if (DnsFilterEngine.isBlocked(query.name)) {
                            DnsPacketEngine.blockedResponse(packet, length)?.let { output.write(it) }
                        } else {
                            forwardDns(packet, length, output)
                        }
                    }
                }
            }
        } catch (_: Exception) {
        } finally {
            stopVpn()
        }
    }

    private fun forwardDns(packet: ByteArray, length: Int, output: FileOutputStream) {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        val udp = ihl
        val dnsStart = udp + 8
        val dnsLength = length - dnsStart
        if (dnsLength <= 0) return

        val dnsQuery = packet.copyOfRange(dnsStart, length)
        DatagramSocket().use { socket ->
            protect(socket)
            socket.soTimeout = 2500
            val request = DatagramPacket(dnsQuery, dnsQuery.size, InetSocketAddress(DNS1, 53))
            socket.send(request)
            val responseBuffer = ByteArray(4096)
            val response = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(response)

            val out = packet.copyOf(ihl + 8 + response.length)
            System.arraycopy(response.data, response.offset, out, dnsStart, response.length)
            swapIpv4(out, 12, 16)
            out[8] = 64.toByte()
            write16(out, ihl + 2, out.size - ihl)
            write16(out, ihl + 6, 0)
            write16(out, ihl + 10, 0)
            write16(out, ihl + 10, checksum(out, 0, ihl))

            val oldSrc0 = out[udp]
            val oldSrc1 = out[udp + 1]
            out[udp] = out[udp + 2]
            out[udp + 1] = out[udp + 3]
            out[udp + 2] = oldSrc0
            out[udp + 3] = oldSrc1
            write16(out, udp + 4, out.size - udp)
            write16(out, udp + 6, 0)
            write16(out, udp + 6, udpChecksum(out, udp, out.size - udp))
            output.write(out)
        }
    }

    private fun startForegroundNotification() {
        val channelId = "nouman_guard"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(channelId, "Nouman Guard", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val notification = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Nouman Guard فعال ہے")
            .setContentText("DNS protection چل رہی ہے۔")
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        startForeground(1001, notification)
    }

    private fun stopVpn() {
        running.set(false)
        try { vpnInterface?.close() } catch (_: Exception) { }
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun u16(b: ByteArray, p: Int): Int = ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF)
    private fun write16(b: ByteArray, p: Int, v: Int) { b[p] = (v ushr 8).toByte(); b[p + 1] = v.toByte() }
    private fun swapIpv4(packet: ByteArray, a: Int, b: Int) { for (i in 0 until 4) { val t = packet[a + i]; packet[a + i] = packet[b + i]; packet[b + i] = t } }
    private fun checksum(packet: ByteArray, start: Int, length: Int): Int { var sum = ones(packet, start, length); while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16); return sum.inv().toInt() and 0xFFFF }
    private fun ones(packet: ByteArray, start: Int, length: Int): Long { var sum = 0L; var i = start; val end = start + length; while (i + 1 < end) { sum += u16(packet, i); i += 2 }; if (i < end) sum += (packet[i].toInt() and 0xFF) shl 8; return sum }
    private fun udpChecksum(packet: ByteArray, udpStart: Int, udpLength: Int): Int { var sum = 0L; for (i in 12..18 step 2) sum += u16(packet, i).toLong(); sum += (packet[9].toInt() and 0xFF).toLong(); sum += udpLength.toLong(); sum += ones(packet, udpStart, udpLength); while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16); return sum.inv().toInt() and 0xFFFF }

    companion object {
        const val ACTION_STOP = "STOP"
        private const val DNS1 = "1.1.1.3"
    }
}
