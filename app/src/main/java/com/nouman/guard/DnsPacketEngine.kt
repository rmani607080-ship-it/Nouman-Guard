package com.nouman.guard

object DnsPacketEngine {

    data class Query(
        val id: Int,
        val name: String,
        val qtype: Int,
        val qclass: Int
    )

    fun parseQuery(packet: ByteArray, length: Int): Query? {
        if (length < 28) return null
        if (packet.size < length) return null

        val version = (packet[0].toInt() ushr 4) and 0x0F
        val ihl = (packet[0].toInt() and 0x0F) * 4

        if (version != 4 || ihl < 20 || length < ihl + 8 + 12) {
            return null
        }

        val totalLength = u16(packet, 2)
        if (totalLength < ihl + 8 || totalLength > length) {
            return null
        }

        val flagsAndOffset = u16(packet, 6)

        if ((flagsAndOffset and 0x1FFF) != 0) {
            return null
        }

        val protocol = packet[9].toInt() and 0xFF

        if (protocol != 17) return null

        val udp = ihl

        val srcPort = u16(packet, udp)
        val dstPort = u16(packet, udp + 2)

        if (dstPort != 53) return null
        if (srcPort == 0) return null

        val udpLength = u16(packet, udp + 4)

        if (udpLength < 8 || udp + udpLength > length) {
            return null
        }

        val dns = udp + 8

        if (dns + 12 > length) return null

        val id = u16(packet, dns)
        val flags = u16(packet, dns + 2)

        if ((flags and 0x8000) != 0) {
            return null
        }

        val qdCount = u16(packet, dns + 4)

        if (qdCount != 1) return null

        var p = dns + 12
        val labels = ArrayList<String>()

        while (p < length) {
            val n = packet[p].toInt() and 0xFF
            p++

            if (n == 0) break

            if ((n and 0xC0) != 0) return null
            if (n > 63) return null
            if (p + n > length) return null

            val label = String(
                packet,
                p,
                n,
                Charsets.US_ASCII
            )

            if (label.isEmpty()) return null

            labels += label
            p += n
        }

        if (labels.isEmpty()) return null
        if (p + 4 > length) return null

        val qtype = u16(packet, p)
        val qclass = u16(packet, p + 2)

        if (qclass != 1) return null

        return Query(
            id = id,
            name = labels.joinToString("."),
            qtype = qtype,
            qclass = qclass
        )
    }

    fun blockedResponse(
        queryPacket: ByteArray,
        length: Int
    ): ByteArray? {

        val query = parseQuery(queryPacket, length) ?: return null

        val ihl = (queryPacket[0].toInt() and 0x0F) * 4
        val udp = ihl
        val dnsStart = udp + 8

        val questionEnd = findQuestionEnd(
            queryPacket,
            length,
            dnsStart + 12
        ) ?: return null

        val questionLength =
            questionEnd - (dnsStart + 12) + 4

        val outLength =
            ihl + 8 + 12 + questionLength

        if (outLength > 4096) return null

        val out = ByteArray(outLength)

        System.arraycopy(
            queryPacket,
            0,
            out,
            0,
            ihl + 8
        )

        System.arraycopy(
            queryPacket,
            dnsStart,
            out,
            dnsStart,
            12 + questionLength
        )

        swapIpv4(out, 12, 16)

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
            checksum(out, 0, ihl)
        )

        val oldSrc0 = out[udp]
        val oldSrc1 = out[udp + 1]

        out[udp] = out[udp + 2]
        out[udp + 1] = out[udp + 3]

        out[udp + 2] = oldSrc0
        out[udp + 3] = oldSrc1

        write16(
            out,
            udp + 4,
            out.size - udp
        )

        write16(out, udp + 6, 0)

        val dns = udp + 8

        val originalFlags =
            u16(queryPacket, dns + 2)

        val responseFlags =
            0x8000 or
            (originalFlags and 0x0100) or
            0x0003

        write16(
            out,
            dns + 2,
            responseFlags
        )

        write16(out, dns + 4, 1)
        write16(out, dns + 6, 0)
        write16(out, dns + 8, 0)
        write16(out, dns + 10, 0)

        write16(
            out,
            udp + 6,
            udpChecksum(
                out,
                udp,
                out.size - udp
            )
        )

        return out
    }

    private fun findQuestionEnd(
        packet: ByteArray,
        length: Int,
        start: Int
    ): Int? {

        var p = start

        while (p < length) {

            val n = packet[p].toInt() and 0xFF
            p++

            if (n == 0) {
                return p
            }

            if ((n and 0xC0) != 0) {
                return null
            }

            if (n > 63 || p + n > length) {
                return null
            }

            p += n
        }

        return null
    }

    private fun udpChecksum(
        packet: ByteArray,
        udpStart: Int,
        udpLength: Int
    ): Int {

        var sum = 0L

        for (i in 12..18 step 2) {
            sum += u16(packet, i).toLong()
        }

        sum += (packet[9].toInt() and 0xFF).toLong()
        sum += udpLength.toLong()

        sum += onesComplementSum(
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

    private fun checksum(
        packet: ByteArray,
        start: Int,
        length: Int
    ): Int {

        var sum =
            onesComplementSum(
                packet,
                start,
                length
            )

        while (sum ushr 16 != 0L) {
            sum =
                (sum and 0xFFFF) +
                (sum ushr 16)
        }

        return sum.inv().toInt() and 0xFFFF
    }

    private fun onesComplementSum(
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

    private fun swapIpv4(
        packet: ByteArray,
        a: Int,
        b: Int
    ) {

        for (i in 0 until 4) {

            val temp = packet[a + i]

            packet[a + i] =
                packet[b + i]

            packet[b + i] =
                temp
        }
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
}