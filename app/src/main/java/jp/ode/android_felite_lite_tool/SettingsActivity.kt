package jp.ode.android_felite_lite_tool

import android.os.Bundle
import android.text.InputType
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.EditTextPreference
import androidx.preference.PreferenceFragmentCompat

class SettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.settings_activity)
        supportFragmentManager
            .beginTransaction()
            .replace(R.id.settings, SettingsFragment())
            .commit()
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return super.onSupportNavigateUp()
    }

    class SettingsFragment : PreferenceFragmentCompat() {
        override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
            setPreferencesFromResource(R.xml.root_preferences, rootKey)

            // 秘密キーをpassword的にmaskする
            // https://stackoverflow.com/questions/57018865/edittextpreference-does-not-mask-password-even-with-androidinputtype-textpassw
            val editTextPreference: EditTextPreference? = findPreference("master_key")
            editTextPreference?.setOnBindEditTextListener {editText ->
                editText.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            editTextPreference?.setOnPreferenceChangeListener { preference, newValue ->
                //logError( "Pref " + preference.key + " changed to " + newValue.toString())
                try {
                    val byteArray =
                        newValue.toString().split(":").map { it -> it.toInt(16).toByte() }
                            .toByteArray()
                    if (byteArray.size == 24) {
                        true
                    } else {
                        AlertDialog.Builder(this.requireContext())
                            .setTitle("エラー")
                            .setMessage("24byte分入力してください. 入力数:${byteArray.size}")
                            .setPositiveButton("OK"){ dialog, which -> }
                            .show()
                        false
                    }
                } catch (e: Exception) {
                    AlertDialog.Builder(this.requireContext())
                        .setTitle("エラー")
                        .setMessage("入力形式が正しくありません")
                        .setPositiveButton("OK"){ dialog, which -> }
                        .show()
                    false
                }
            }

        }
    }
}