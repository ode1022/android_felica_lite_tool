package jp.ode.android_felite_lite_tool

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.NfcF
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.PreferenceManager
import jp.ode.android_felite_lite_tool.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var mNfcAdapter: NfcAdapter
    private var pendingIntent: PendingIntent? = null
    private var intentFilters: Array<IntentFilter>? = null
    private var techLists: Array<Array<String>>? = null
    private lateinit var binding: ActivityMainBinding;

    private var issuanceFelicaMode = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        //setContentView(R.layout.activity_main)
        binding = ActivityMainBinding.inflate(layoutInflater)
        binding.modeButton.setOnClickListener{
            issuanceFelicaMode = !issuanceFelicaMode
            if (issuanceFelicaMode) {
                binding.issuanceFelicaModeText.text = getString(R.string.issuanceModeText)
                binding.modeButton.text = getString(R.string.authModeButtonText)
            } else {
                binding.issuanceFelicaModeText.text = getString(R.string.authModeText)
                binding.modeButton.text = getString(R.string.issuanceModeButtonText)
            }
            binding.resultText.text = ""
            binding.idmText.text = ""
        }
        binding.settingButton.setOnClickListener{
            startActivity(Intent(this@MainActivity, SettingsActivity::class.java))

        }

        setContentView(binding.root)


        val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        pendingIntent = PendingIntent.getActivity(this, 0, intent, 0)

        // 受け取るIntentを指定
        intentFilters = arrayOf(IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED))

        // 反応するタグの種類を指定
        techLists = arrayOf(
            arrayOf(android.nfc.tech.Ndef::class.java.name),
            arrayOf(android.nfc.tech.NdefFormatable::class.java.name),
            arrayOf(NfcF::class.java.name)
            )

        mNfcAdapter = NfcAdapter.getDefaultAdapter(applicationContext)
    }


    override fun onResume() {
        super.onResume()

        // NFCタグの検出を有効化
        mNfcAdapter?.enableForegroundDispatch(this, pendingIntent, intentFilters, techLists)
    }

    /**
     * NFCタグの検出時に呼ばれる
     */
    override fun onNewIntent(intent: Intent) {

        // タグのIDを取得
        val tagId : ByteArray = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID) ?: return

        var list = ArrayList<String>()
        for(byte in tagId) {
            list.add(String.format("%02X", byte.toInt() and 0xFF))
        }

        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        val masterKey = prefs.getString("master_key", "")
        if (masterKey == "") {
            Toast.makeText(this, "設定画面でマスターキーを設定してください", Toast.LENGTH_SHORT).show()
            return
        }

        val reader = NfcFReader(masterKey)

        val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG) ?: return
        val result = reader.read(tag, this) { reader : NfcFReader ->
            if (issuanceFelicaMode) {
                reader.issuanceFelica()
                Toast.makeText(this, "発行OK", Toast.LENGTH_SHORT).show()
                binding.resultText.text = "発行OK"
            } else {
                when (reader.checkMac()) {
                    0 -> {
                        Toast.makeText(this, "認証OK", Toast.LENGTH_SHORT).show()
                        binding.resultText.text = "認証OK"
                    }
                    -1 -> {
                        Toast.makeText(this, "認証NG", Toast.LENGTH_SHORT).show()
                        binding.resultText.text = "認証NG"
                    }
                    -2 -> {
                        Toast.makeText(this, "接続エラー", Toast.LENGTH_SHORT).show()
                        binding.resultText.text = "接続エラー"
                    }
                }
            }
        }
//        Toast.makeText(this, "tag: '$tag', id: '${tag.id.joinToString(" ")}'", Toast.LENGTH_SHORT).show()
        println("tag.id: "+tag.id.toHexString())
        binding.idmText.text = tag.id.toHexString()

        // 画面に表示
//        var tagTextView: TextView = findViewById(R.id.tagText)
//        tagTextView.text = list.joinToString(":")
        //Toast.makeText(this, "idm="+list.joinToString(":"), Toast.LENGTH_SHORT).show()
    }

    override fun onPause() {
        super.onPause()

        mNfcAdapter?.disableForegroundDispatch(this)
    }
}

