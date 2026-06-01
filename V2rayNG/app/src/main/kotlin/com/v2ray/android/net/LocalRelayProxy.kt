package com.v2ray.android.net

import android.util.Log
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer

class LocalRelayProxy(
    private val listenPort: Int = 40443,
    private val targetHost: String,
    private val targetPort: Int
) {
    private var serverSocket: ServerSocket? = null
    private var scope = CoroutineScope(Dispatchers.IO + Job())
    private val TAG = "LocalRelayProxy"
    private val extractedSNIs = mutableMapOf<String, String>()

    fun start() {
        scope.launch {
            try {
                serverSocket = ServerSocket(listenPort, 50, InetAddress.getByName("127.0.0.1"))
                Log.i(TAG, "Local relay listening on 127.0.0.1:$listenPort -> $targetHost:$targetPort")
                
                while (isActive) {
                    val clientSocket = serverSocket?.accept() ?: break
                    launch {
                        handleClient(clientSocket)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Relay error: ${e.message}")
            }
        }
    }

    /**
     * Extract SNI from TLS ClientHello (first packet)
     * Parses raw bytes to find the Server Name Indication extension
     */
    private fun extractSNI(data: ByteArray): String? {
        try {
            // TLS Record Header: [ContentType(1)] [Version(2)] [Length(2)]
            if (data.size < 5) return null
            
            val contentType = data[0].toInt()
            if (contentType != 0x16) { // 0x16 = Handshake
                Log.d(TAG, "Not a TLS handshake packet")
                return null
            }

            // Parse Handshake Header: [HandshakeType(1)] [Length(3)]
            if (data.size < 9) return null
            
            val handshakeType = data[5].toInt()
            if (handshakeType != 0x01) { // 0x01 = ClientHello
                Log.d(TAG, "Not a ClientHello packet")
                return null
            }

            // ClientHello structure:
            // [ProtocolVersion(2)] [Random(32)] [SessionIDLength(1)] [SessionID(variable)]
            // [CipherSuitesLength(2)] [CipherSuites(variable)]
            // [CompressionMethodsLength(1)] [CompressionMethods(variable)]
            // [ExtensionsLength(2)] [Extensions(variable)]

            var offset = 43 // Skip fixed header + version + random
            
            if (offset >= data.size) return null

            // Skip Session ID
            val sessionIdLen = (data[offset].toInt()) and 0xFF
            offset += 1 + sessionIdLen

            if (offset + 2 > data.size) return null

            // Skip Cipher Suites
            val cipherSuitesLen = ((data[offset].toInt() and 0xFF) shl 8) or
                    (data[offset + 1].toInt() and 0xFF)
            offset += 2 + cipherSuitesLen

            if (offset >= data.size) return null

            // Skip Compression Methods
            val compressionLen = (data[offset].toInt()) and 0xFF
            offset += 1 + compressionLen

            if (offset + 2 > data.size) return null

            // Parse Extensions
            val extensionsLen = ((data[offset].toInt() and 0xFF) shl 8) or
                    (data[offset + 1].toInt() and 0xFF)
            offset += 2

            val extensionsEnd = offset + extensionsLen
            if (extensionsEnd > data.size) return null

            while (offset < extensionsEnd - 3) {
                val extensionType = ((data[offset].toInt() and 0xFF) shl 8) or
                        (data[offset + 1].toInt() and 0xFF)
                offset += 2

                val extensionLen = ((data[offset].toInt() and 0xFF) shl 8) or
                        (data[offset + 1].toInt() and 0xFF)
                offset += 2

                // Extension Type 0x0000 = server_name (SNI)
                if (extensionType == 0x0000) {
                    return parseSNIExtension(data, offset, extensionLen)
                }

                offset += extensionLen
            }

            Log.d(TAG, "No SNI extension found in ClientHello")
            return null

        } catch (e: Exception) {
            Log.e(TAG, "SNI extraction failed: ${e.message}")
            return null
        }
    }

    /**
     * Parse the SNI extension data to extract the hostname
     */
    private fun parseSNIExtension(data: ByteArray, offset: Int, length: Int): String? {
        try {
            // SNI Extension Format:
            // [ListLength(2)] [NameType(1)] [NameLength(2)] [Name(variable)]
            
            if (offset + 5 > data.size) return null

            val listLen = ((data[offset].toInt() and 0xFF) shl 8) or
                    (data[offset + 1].toInt() and 0xFF)
            var pos = offset + 2

            while (pos < offset + 2 + listLen) {
                if (pos >= data.size) break

                val nameType = (data[pos].toInt()) and 0xFF
                pos++

                if (pos + 2 > data.size) break

                val nameLen = ((data[pos].toInt() and 0xFF) shl 8) or
                        (data[pos + 1].toInt() and 0xFF)
                pos += 2

                if (pos + nameLen > data.size) break

                if (nameType == 0x00) { // host_name
                    val sniBytes = data.copyOfRange(pos, pos + nameLen)
                    val sni = String(sniBytes, Charsets.US_ASCII)
                    Log.i(TAG, "Extracted SNI: $sni")
                    return sni
                }

                pos += nameLen
            }

            return null

        } catch (e: Exception) {
            Log.e(TAG, "SNI extension parsing failed: ${e.message}")
            return null
        }
    }

    /**
     * Resolve hostname to IP address (dynamic DNS resolution)
     */
    private suspend fun resolveSNI(sni: String): String? = withContext(Dispatchers.IO) {
        try {
            val ipAddr = InetAddress.getByName(sni).hostAddress
            Log.i(TAG, "Resolved SNI '$sni' to IP: $ipAddr")
            return@withContext ipAddr
        } catch (e: Exception) {
            Log.e(TAG, "Failed to resolve SNI '$sni': ${e.message}")
            return@withContext null
        }
    }

    private suspend fun handleClient(clientSocket: Socket) {
        var remoteSocket: Socket? = null
        try {
            val clientAddr = "${clientSocket.inetAddress.hostAddress}:${clientSocket.port}"
            Log.i(TAG, "New client connection: $clientAddr")

            // Read first packet to extract SNI
            val firstPacket = ByteArray(16384)
            val bytesRead = clientSocket.inputStream.read(firstPacket)
            
            if (bytesRead <= 0) {
                Log.w(TAG, "No data from client")
                clientSocket.close()
                return
            }

            val packet = firstPacket.copyOf(bytesRead)
            Log.d(TAG, "Received ${bytesRead} bytes from client")

            // Attempt SNI extraction
            var sni: String? = null
            var resolvedIP: String? = null
            
            sni = extractSNI(packet)
            if (sni != null) {
                resolvedIP = resolveSNI(sni)
                Log.i(TAG, "[$clientAddr] SNI: $sni -> Resolved: $resolvedIP")
                extractedSNIs[clientAddr] = sni
            } else {
                Log.d(TAG, "[$clientAddr] No SNI found, using default target: $targetHost:$targetPort")
            }

            // Determine connection target
            val finalHost = resolvedIP ?: targetHost
            val finalPort = targetPort

            // Connect to remote server
            remoteSocket = Socket(finalHost, finalPort)
            Log.i(TAG, "[$clientAddr] Connected to remote: $finalHost:$finalPort")

            // Write the captured first packet to remote
            remoteSocket.outputStream.write(packet)
            remoteSocket.outputStream.flush()

            // Bidirectional relay for remaining traffic
            launch { 
                relayStream(clientSocket.inputStream, remoteSocket.outputStream, "$clientAddr -> remote") 
            }
            launch { 
                relayStream(remoteSocket.inputStream, clientSocket.outputStream, "remote -> $clientAddr") 
            }

        } catch (e: Exception) {
            Log.e(TAG, "Client handling failed: ${e.message}")
        } finally {
            remoteSocket?.close()
            clientSocket.close()
        }
    }

    private suspend fun relayStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        direction: String
    ) = withContext(Dispatchers.IO) {
        try {
            val buffer = ByteArray(16384)
            var bytesRead: Int
            var totalBytes: Long = 0

            while (inputStream.read(buffer).also { bytesRead = it } > 0) {
                outputStream.write(buffer, 0, bytesRead)
                outputStream.flush()
                totalBytes += bytesRead
            }
            
            Log.d(TAG, "Stream closed ($direction): $totalBytes bytes transferred")
        } catch (e: Exception) {
            Log.d(TAG, "Stream error ($direction): ${e.message}")
        }
    }

    /**
     * Get statistics on extracted SNIs
     */
    fun getExtractedSNIs(): Map<String, String> = extractedSNIs.toMap()

    fun stop() {
        scope.cancel()
        serverSocket?.close()
        Log.i(TAG, "Local relay stopped. Extracted SNIs: ${extractedSNIs.size}")
    }

    companion object {
        /**
         * Create a LocalRelayProxy from the currently selected server in v2rayNG
         */
        fun createFromSelectedServer(
            listenPort: Int = 40443
        ): LocalRelayProxy? {
            // This requires v2rayNG context, implementation in MainActivity
            return null
        }
    }
}
