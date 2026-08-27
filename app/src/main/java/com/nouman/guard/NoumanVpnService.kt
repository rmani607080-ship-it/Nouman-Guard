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

    private val running =
        AtomicBoolean(false)

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int
    ): Int {

        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        if (running.get()) {
            return START_STICKY
        }

        startForegroundNotification()

        running.set(true)

        vpnThread =
            Thread(
                this,
                "NoumanGuardDnsVpn"
            ).also {
                it.start()
            }

        return START_STICKY
    }

    override fun run() {

        try {

            vpnInterface =
                Builder()
                    .setSession(
                        "Nouman Guard DNS Protection"
                    )
                    .setMtu(1500)
                    .addAddress(
                        "10.10.0.2",
                        32
                    )
                    .addRoute(
                        DNS_PRIMARY,
                        32
                    )
                    .addRoute(
                        DNS_SECONDARY,
                        32
                    )
                    .addDnsServer(
                        DNS_PRIMARY
                    )
                    .addDnsServer(
                        DNS_SECONDARY
                    )
                    .establish()

            val interfaceFd =
                vpnInterface ?: return

            FileInputStream(
                interfaceFd.fileDescriptor
            ).use { input ->

                FileOutputStream(
                    interfaceFd.fileDescriptor
                ).use { output ->

                    val buffer =
                        ByteArray(32767)

                    while (running.get()) {

                        val length =
                            try {
                                input.read(buffer)
                            } catch (_: Exception) {
                                break
                            }

                        if (length <= 0) {
                            continue
                        }

                        val packet =
                            buffer.copyOf(length)

                        val query =
                            try {
                                DnsPacketEngine.parseQuery(
                                    packet,
                                    length
                                )
                            } catch (_: Exception) {
                                null
                            }

                        if (query == null) {
                            continue
                        }

                        if (
                            DnsFilterEngine.isBlocked(
                                query.name
                            )
                        ) {

                            try {

                                DnsPacketEngine
                                    .blockedResponse(
                                        packet,
                                        length
                                    )
                                    ?.let {
                                        output.write(it)
                                    }

                            } catch (_: Exception) {
                            }

                        } else {

                            try {
                                forwardDns(
                                    packet,
                                    length,
                                    output
                                )
                            } catch (_: Exception) {
                            }
                        }
                    }
                }
            }

        } catch (_: Exception) {
        } finally {
            stopVpn()
        }
    }

    private fun forwardDns(
        packet: ByteArray,
        length: Int,
        output: FileOutputStream
    ) {

        if (length < 28) return

        val ihl =
            (packet[0].toInt() and 0x0F) * 4

        if (ihl < 20 || ihl + 8 > length) {
            return
        }

        val dnsStart =
            ihl + 8

        val dnsLength =
            length - dnsStart

        if (dnsLength <= 0 || dnsLength > 4096) {
            return
        }

        val dnsQuery =
            packet.copyOfRange(
                dnsStart,
                length
            )

        val response =
            queryDnsServer(
                dnsQuery,
                DNS_PRIMARY
            ) ?: queryDnsServer(
                dnsQuery,
                DNS_SECONDARY
            ) ?: return

        val responseLength =
            response.size

        if (responseLength <= 0 ||
            responseLength > 4096
        ) {
            return
        }

        val out =
            packet.copyOf(
                ihl + 8 + responseLength
            )

        System.arraycopy(
            response,
            0,
            out,
            dnsStart,
            responseLength
        )

        swapIpv4(
            out,
            12,
            16
        )

        out[8] = 64.toByte()

        write16(
            out,
            ihl + 2,
            out.size - ihl
        )

        write16(out, ihl + 6, 0)
        write16(out, ihl + 10, 0)

        write16(
            out,
            ihl + 10,
            checksum(
                out,
                0,
                ihl
            )
        )

        val oldSrc0 =
            out[ihl]

        val oldSrc1 =
            out[ihl + 1]

        out[ihl] =
            out[ihl + 2]

        out[ihl + 1] =
            out[ihl + 3]

        out[ihl + 2] =
            oldSrc0

        out[ihl + 3] =
            oldSrc1

        write16(
            out,
            ihl + 4,
            out.size - ihl
        )

        write16(
            out,
            ihl + 6,
            0
        )

        write16(
            out,
            ihl + 6,
            udpChecksum(
                out,
                ihl,
                out.size - ihl
            )
        )

        output.write(out)
    }

    private fun queryDnsServer(
        dnsQuery: ByteArray,
        server: String
    ): ByteArray? {

        DatagramSocket().use { socket ->

            if (!protect(socket)) {
                return null
            }

            socket.soTimeout = DNS_TIMEOUT_MS

            val request =
                DatagramPacket(
                    dnsQuery,
                    dnsQuery.size,
                    InetSocketAddress(
                        server,
                        DNS_PORT
                    )
                )

            socket.send(request)

            val responseBuffer =
                ByteArray(4096)

            val response =
                DatagramPacket(
                    responseBuffer,
                    responseBuffer.size
                )

            socket.receive(response)

            if (response.length < 12) {
                return null
            }

            return response.data.copyOfRange(
                response.offset,
                response.offset + response.length
            )
        }
    }

    private fun startForegroundNotification() {

        val channelId =
            "nouman_guard"

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.O
        ) {

            val manager =
                getSystemService(
                    NotificationManager::class.java
                )

            manager.createNotificationChannel(
                NotificationChannel(
                    channelId,
                    "Nouman Guard",
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }

        val notification =
            NotificationCompat.Builder(
                this,
                channelId
            )
                .setSmallIcon(
                    android.R.drawable.ic_lock_lock
                )
                .setContentTitle(
                    "Nouman Guard فعال ہے"
                )
                .setContentText(
                    "DNS protection چل رہی ہے۔"
                )
                .setOngoing(true)
                .setPriority(
                    NotificationCompat.PRIORITY_LOW
                )
                .build()

        startForeground(
            NOTIFICATION_ID,
            notification
        )
    }

    private fun stopVpn() {

        if (!running.getAndSet(false)) {
            return
        }

        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }

        vpnInterface = null

        vpnThread = null

        try {
            stopForeground(
                STOP_FOREGROUND_REMOVE
            )
        } catch (_: Exception) {
        }

        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun u16(
        packet: ByteArray,
        position: Int
    ): Int {

        return (
            (packet[position].toInt() and 0xFF) shl 8
        ) or (
            packet[position + 1].toInt() and 0xFF
        )
    }

    private fun write16(
        packet: ByteArray,
        position: Int,
        value: Int
    ) {

        packet[position] =
            (value ushr 8).toByte()

        packet[position + 1] =
            value.toByte()
    }

    private fun swapIpv4(
        packet: ByteArray,
        a: Int,
        b: Int
    ) {

        for (i in 0 until 4) {

            val temp =
                packet[a + i]

            packet[a + i] =
                packet[b + i]

            packet[b + i] =
                temp
        }
    }

    private fun checksum(
        packet: ByteArray,
        start: Int,
        length: Int
    ): Int {

        var sum =
            ones(packet, start, length)

        while (sum ushr 16 != 0L) {
            sum =
                (sum and 0xFFFF) +
                (sum ushr 16)
        }

        return sum.inv().toInt() and 0xFFFF
    }

    private fun ones(
        packet: ByteArray,
        start: Int,
        length: Int
    ): Long {

        var sum = 0L
        var i = start
        val end = start + length

        while (i + 1 < end) {
            sum += u16(packet, i)
            i += 2
        }

        if (i < end) {
            sum +=
                (packet[i].toInt() and 0xFF) shl 8
        }

        return sum
    }

    private fun udpChecksum(
        packet: ByteArray,
        udpStart: Int,
        udpLength: Int
    ): Int {

        var sum = 0L

        for (i in 12..18 step 2) {
            sum +=
                u16(packet, i).toLong()
        }

        sum +=
            (packet[9].toInt() and 0xFF).toLong()

        sum += udpLength.toLong()

        sum +=
            ones(
                packet,
                udpStart,
                udpLength
            )

        while (sum ushr 16 != 0L) {
            sum =
                (sum and 0xFFFF) +
                (sum ushr 16)
        }

        return sum.inv().toInt() and 0xFFFF
    }

    companion object {

        const val ACTION_STOP =
            "com.nouman.guard.STOP"

        private const val DNS_PRIMARY =
            "1.1.1.3"

        private const val DNS_SECONDARY =
            "1.0.0.3"

        private const val DNS_PORT = 53

        private const val DNS_TIMEOUT_MS = 1200

        private const val NOTIFICATION_ID = 1001
    }
}