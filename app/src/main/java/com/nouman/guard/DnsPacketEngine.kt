package com.nouman.guard

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

object DnsPacketEngine {
    data class Query(val id: Int, val name: String, val qtype: Int, val qclass: Int)

    fun parseQuery(packet: ByteArray, length: Int): Query? {
        if (length < 29) return null
        val version = packet[0].toInt() ushr 4
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (version != 4 || ihl < 20 || length < ihl + 12) return null
        if ((packet[ihl + 2].toInt() and 0x80) != 0) return null
        if ((packet[ihl + 2].toInt() and 0x0F) != 0) return null
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return null
        val udp = ihl
        val dstPort = u16(packet, udp + 2)
        if (dstPort != 53) return null
        val dns = udp + 8
        val id = u16(packet, dns)
        val qdCount = u16(packet, dns + 4)
        if (qdCount < 1) return null
        var p = dns + 12
        val labels = ArrayList<String>()
        while (p < length) {
            val n = packet[p].toInt() and 0xFF
            p++
            if (n == 0) break
            if ((n and 0xC0) != 0 || p + n > length) return null
            labels += String(packet, p, n, Charsets.US_ASCII)
            p += n
        }
        if (labels.isEmpty() || p + 4 > length) return null
        return Query(id, labels.joinToString("."), u16(packet, p), u16(packet, p + 2))
    }

    fun blockedResponse(queryPacket: ByteArray, length: Int): ByteArray? {
        val q = parseQuery(queryPacket, length) ?: return null
        val ihl = (queryPacket[0].toInt() and 0x0F) * 4
        val dnsStart = ihl + 8
        val questionEnd = findQuestionEnd(queryPacket, length, dnsStart + 12) ?: return null
        val dnsQuestionLength = questionEnd - (dnsStart + 12) + 4
        val out = ByteArray(ihl + 8 + 12 + dnsQuestionLength)
        System.arraycopy(queryPacket, 0, out, 0, ihl + 8)
        System.arraycopy(queryPacket, ihl + 8, out, ihl + 8, 12 + dnsQuestionLength)

        swapIpv4(out, 12, 16)
        out[8] = 64.toByte()
        write16(out, ihl + 2, out.size - ihl)
        write16(out, ihl + 6, 0)
        write16(out, ihl + 10, 0)
        write16(out, ihl + 10, checksum(out, 0, ihl))

        val udp = ihl
        val oldSrc = out.copyOfRange(udp, udp + 2)
        out[udp] = out[udp + 2]
        out[udp + 1] = out[udp + 3]
        out[udp + 2] = oldSrc[0]
        out[udp + 3] = oldSrc[1]
        write16(out, udp + 4, out.size - udp)
        write16(out, udp + 6, 0)

        val dns = udp + 8
        out[dns + 2] = 0x81.toByte()
        out[dns + 3] = 0x83.toByte()
        out[dns + 4] = 0
        out[dns + 5] = 1
        out[dns + 6] = 0
        out[dns + 7] = 0
        out[dns + 8] = 0
        out[dns + 9] = 0
        out[dns + 10] = 0
        out[dns + 11] = 0

        write16(out, udp + 6, udpChecksum(out, udp, out.size - udp))
        return out
    }

    private fun findQuestionEnd(packet: ByteArray, length: Int, start: Int): Int? {
        var p = start
        while (p < length) {
            val n = packet[p].toInt() and 0xFF
            p++
            if (n == 0) return p
            if ((n and 0xC0) != 0 || p + n > length) return null
            p += n
        }
        return null
    }

    private fun udpChecksum(packet: ByteArray, udpStart: Int, udpLength: Int): Int {
        var sum = 0L
        for (i in 12..18 step 2) sum += u16(packet, i).toLong()
        sum += (packet[9].toInt() and 0xFF).toLong()
        sum += udpLength.toLong()
        sum += onesComplementSum(packet, udpStart, udpLength)
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun checksum(packet: ByteArray, start: Int, length: Int): Int {
        var sum = onesComplementSum(packet, start, length).toLong()
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun onesComplementSum(packet: ByteArray, start: Int, length: Int): Long {
        var sum = 0L
        var i = start
        val end = start + length
        while (i + 1 < end) {
            sum += u16(packet, i)
            i += 2
        }
        if (i < end) sum += (packet[i].toInt() and 0xFF) shl 8
        return sum
    }

    private fun swapIpv4(packet: ByteArray, a: Int, b: Int) {
        for (i in 0 until 4) {
            val t = packet[a + i]
            packet[a + i] = packet[b + i]
            packet[b + i] = t
        }
    }

    private fun u16(b: ByteArray, p: Int): Int = ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF)
    private fun write16(b: ByteArray, p: Int, v: Int) { b[p] = (v ushr 8).toByte(); b[p + 1] = v.toByte() }
}
