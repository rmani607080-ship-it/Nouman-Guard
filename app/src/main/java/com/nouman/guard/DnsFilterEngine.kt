package com.nouman.guard

import java.util.Locale

object DnsFilterEngine {

    private val blockedDomains = setOf(
        "pornhub.com",
        "xvideos.com",
        "xnxx.com",
        "redtube.com",
        "youporn.com",
        "xhamster.com",
        "beeg.com",
        "tube8.com",
        "spankbang.com"
    )

    fun isBlocked(domain: String): Boolean {
        val clean = domain
            .trim()
            .trimEnd('.')
            .lowercase(Locale.US)

        if (clean.isEmpty()) return false

        return blockedDomains.any {
            clean == it || clean.endsWith(".$it")
        }
    }

    fun blockedList(): List<String> {
        return blockedDomains.sorted()
    }
}