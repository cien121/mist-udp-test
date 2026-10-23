package com.chan.mistudptest

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import misttest.Misttest
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    // Test account (lab only)
    private val testCid = "a57a9111fafe96a7c93fe7a043a7cf2d"
    private val testKey = "y9H2aR9AyxO6Oz4TrDUUyPAPgxBEpNuF4EKcsVYEpQM="

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val serverInput = findViewById<EditText>(R.id.serverInput)
        val connectBtn = findViewById<Button>(R.id.connectBtn)
        val logView = findViewById<TextView>(R.id.logView)
        val scrollView = findViewById<ScrollView>(R.id.scrollView)

        serverInput.setText("10.8.0.1:1443")

        fun appendLog(text: String) {
            runOnUiThread {
                logView.append(text + "\n")
                scrollView.post { scrollView.fullScroll(ScrollView.FOCUS_DOWN) }
            }
        }

        connectBtn.setOnClickListener {
            connectBtn.isEnabled = false
            logView.text = ""
            appendLog("Starting test...")

            thread {
                try {
                    val server = serverInput.text.toString().trim()
                    appendLog("Calling Go handshake...")
                    val result = Misttest.runHandshake(server, testCid, testKey)
                    appendLog(result.log)
                    appendLog(if (result.success) ">>> SUCCESS <<<" else ">>> FAILED <<<")
                } catch (e: Exception) {
                    appendLog("EXCEPTION: ${e.message}")
                    e.printStackTrace()
                } finally {
                    runOnUiThread { connectBtn.isEnabled = true }
                }
            }
        }
    }
}
