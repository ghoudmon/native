package com.anonymous.bulwarkmobile

import android.net.DnsResolver
import android.os.Build
import android.os.CancellationSignal
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableArray
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.Executors

/**
 * Native DNS bridge — exposes SRV record lookup to JS. The platform's
 * `java.net.InetAddress` only handles A/AAAA, so JMAP auto-discovery
 * (`_jmap._tcp.<domain>`) requires going through `android.net.DnsResolver`
 * (API 29+) and building/parsing the DNS wire format manually.
 */
class BulwarkDnsModule(reactContext: ReactApplicationContext)
    : ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = MODULE_NAME

    @ReactMethod
    fun resolveSrv(name: String, promise: Promise) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            promise.reject(
                "unsupported",
                "SRV lookup requires Android 10 (API 29) or newer",
            )
            return
        }
        val query = try {
            buildQuery(name, TYPE_SRV)
        } catch (e: Exception) {
            promise.reject("bad_args", e.message ?: "invalid name", e)
            return
        }

        val resolver = DnsResolver.getInstance()
        val signal = CancellationSignal()
        try {
            resolver.rawQuery(
                /* network */ null,
                /* query */ query,
                /* flags */ DnsResolver.FLAG_EMPTY,
                /* executor */ executor,
                /* cancellationSignal */ signal,
                object : DnsResolver.Callback<ByteArray> {
                    override fun onAnswer(answer: ByteArray, rcode: Int) {
                        if (rcode != 0) {
                            promise.reject("dns_rcode", "DNS rcode $rcode")
                            return
                        }
                        try {
                            val records = parseSrvAnswer(answer)
                            val out: WritableArray = Arguments.createArray()
                            for (r in records) {
                                val m = Arguments.createMap()
                                m.putInt("priority", r.priority)
                                m.putInt("weight", r.weight)
                                m.putInt("port", r.port)
                                m.putString("target", r.target)
                                out.pushMap(m)
                            }
                            promise.resolve(out)
                        } catch (e: Exception) {
                            promise.reject(
                                "parse_failed",
                                e.message ?: "could not parse DNS response",
                                e,
                            )
                        }
                    }

                    override fun onError(error: DnsResolver.DnsException) {
                        promise.reject(
                            "dns_failed",
                            error.message ?: "DNS lookup failed",
                            error,
                        )
                    }
                },
            )
        } catch (e: Exception) {
            promise.reject("dns_failed", e.message ?: "DNS lookup failed", e)
        }
    }

    // ── wire format helpers ─────────────────────────────────────

    private data class SrvRecord(
        val priority: Int,
        val weight: Int,
        val port: Int,
        val target: String,
    )

    private fun buildQuery(name: String, qtype: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val dos = DataOutputStream(out)
        // Header: id=0 (kernel fills in), recursion desired, 1 question.
        dos.writeShort(0)
        dos.writeShort(0x0100)
        dos.writeShort(1)
        dos.writeShort(0)
        dos.writeShort(0)
        dos.writeShort(0)

        // QNAME: length-prefixed labels, null terminator.
        for (label in name.trimEnd('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            if (bytes.size > 63) throw IllegalArgumentException("DNS label too long")
            dos.writeByte(bytes.size)
            dos.write(bytes)
        }
        dos.writeByte(0)

        dos.writeShort(qtype)
        dos.writeShort(CLASS_IN)
        return out.toByteArray()
    }

    private fun parseSrvAnswer(data: ByteArray): List<SrvRecord> {
        val buf = ByteBuffer.wrap(data)
        if (buf.remaining() < 12) throw IllegalStateException("Truncated DNS header")
        // id (2) + flags (2)
        buf.position(buf.position() + 4)
        val qdcount = buf.short.toInt() and 0xFFFF
        val ancount = buf.short.toInt() and 0xFFFF
        // nscount + arcount
        buf.position(buf.position() + 4)

        // Skip questions: name + qtype(2) + qclass(2)
        repeat(qdcount) {
            readName(data, buf)
            buf.position(buf.position() + 4)
        }

        val out = mutableListOf<SrvRecord>()
        repeat(ancount) {
            readName(data, buf)
            val type = buf.short.toInt() and 0xFFFF
            // class(2) + ttl(4)
            buf.position(buf.position() + 6)
            val rdlength = buf.short.toInt() and 0xFFFF
            val rdStart = buf.position()
            if (type == TYPE_SRV) {
                val priority = buf.short.toInt() and 0xFFFF
                val weight = buf.short.toInt() and 0xFFFF
                val port = buf.short.toInt() and 0xFFFF
                val target = readName(data, buf).trimEnd('.')
                out.add(SrvRecord(priority, weight, port, target))
            }
            // Seek to the end of this record regardless of type — guards
            // against SRV records with unexpected trailing bytes and lets
            // us silently skip non-SRV answers (CNAME chains, etc.).
            buf.position(rdStart + rdlength)
        }
        return out
    }

    private fun readName(data: ByteArray, buf: ByteBuffer): String {
        val sb = StringBuilder()
        var jumped = false
        var savedPos = -1
        var hops = 0
        var pos = buf.position()
        while (true) {
            if (pos >= data.size) throw IllegalStateException("Truncated DNS name")
            val len = data[pos].toInt() and 0xFF
            if (len == 0) {
                pos += 1
                break
            }
            if ((len and 0xC0) == 0xC0) {
                // Pointer — 14-bit offset into the message.
                if (pos + 1 >= data.size) throw IllegalStateException("Truncated DNS pointer")
                val offset = ((len and 0x3F) shl 8) or (data[pos + 1].toInt() and 0xFF)
                if (!jumped) {
                    savedPos = pos + 2
                    jumped = true
                }
                pos = offset
                if (++hops > 16) throw IllegalStateException("DNS pointer loop")
                continue
            }
            if (sb.isNotEmpty()) sb.append('.')
            pos += 1
            sb.append(String(data, pos, len, Charsets.US_ASCII))
            pos += len
        }
        buf.position(if (jumped) savedPos else pos)
        return sb.toString()
    }

    companion object {
        const val MODULE_NAME = "BulwarkDns"
        private const val TYPE_SRV = 33
        private const val CLASS_IN = 1

        // Bridge calls land on the JS-thread executor by default; spin
        // SRV lookups onto a small pool so multiple discoveries don't
        // serialise on a single thread.
        private val executor = Executors.newCachedThreadPool { r ->
            Thread(r, "BulwarkDns").apply { isDaemon = true }
        }
    }
}
