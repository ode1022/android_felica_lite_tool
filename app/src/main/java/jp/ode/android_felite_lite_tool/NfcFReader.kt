package jp.ode.android_felite_lite_tool;

import android.content.Context;
import android.nfc.Tag;
import android.nfc.tech.NfcF;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import kotlin.experimental.and;
import kotlin.experimental.or;
import kotlin.experimental.xor;

fun ByteArray.toHexString()=joinToString(":"){"%02x".format(it)}

class NfcFReader(masterKey: String) {
    //個別化マスター鍵
    val mk1 : ByteArray
    val mk2 : ByteArray
    val mk3 : ByteArray

    init {
        val byteArray = masterKey.split(":").map {it -> it.toInt(16).toByte()}.toByteArray()
        mk1 = byteArray.copyOfRange(0, 8)
        mk2 = byteArray.copyOfRange(8, 16)
        mk3 = byteArray.copyOfRange(16, 24)

//        println("mk1: "+mk1.toHexString())
//        println("mk2: "+mk2.toHexString())
//        println("mk3: "+mk3.toHexString())
    }

    lateinit var targetIDm : ByteArray
    lateinit var nfc : NfcF

    val FELICA_SERVICE_RO = 0x000B
    val FELICA_SERVICE_RW = 0x0009

    val ADDRESS_RC = 0x80
    val ADDRESS_ID = 0x82
    val ADDRESS_CKV = 0x86
    val ADDRESS_CK = 0x87
    val ADDRESS_MAC_A = 0x91

    fun byteArrayOfInts(vararg ints:Int) = ByteArray(ints.size) { pos -> ints[pos].toByte() }

    //鍵バージョンの書き込み
    // 先頭 2 バイトのみ任意 の値に書き換えが可能です。データ配置を図 3-12 に示します。(FeliCa Lite-S ユーザーズマニュアル P27より)
    val ckv = byteArrayOfInts(0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

    /**
     * NFCデバイスと接続し、通信をする。
     *
     * @param tag 検出した NFCデバイス
     */
    fun read(tag:Tag, contxt:Context, func: (reader: NfcFReader) -> Unit) {
        // NfcF オブジェクトの取得をする。
        this.nfc = NfcF.get(tag)
        try {
            // NFCデバイスに接続する。
            nfc?.connect()

            targetIDm = tag.id

            func(this)

            // NFCデバイスとの接続を切断する。
            nfc.close()

        } catch (e:Exception){
            Log.e("FeliCaSample", "cannot read nfc. '$e'", e)
            if (nfc.isConnected) {
                nfc.close()
            }
        }
    }

    /*
      カードの0.5次発行
    */
    fun issuanceFelica() {
        //カード鍵の書き込み
        //カード鍵の設定（書き込み） ブロック135番(0x87番=CKブロック)の内容を16進数[bb]で書き込む
        val ck = generatePersonalizedCK()

        writeWithoutEncryption(FELICA_SERVICE_RW, ADDRESS_CK, ck)

        //書き込んだカード鍵の内容を確認
        if (checkMac() != 0) {
            throw Exception("書き込んだカード鍵の内容を確認 失敗")
        }

        //鍵バージョンの書き込み
        //ブロック134番(0x86番=CKVブロック)の内容を16進数[bb]で書き込む
        writeWithoutEncryption(FELICA_SERVICE_RW, ADDRESS_CKV, ckv)

        //書き込んだCKVと読み出したCKVを比較
        val value = readWithoutEncryption(ADDRESS_CKV, FELICA_SERVICE_RW)
        if (!ckv.contentEquals(value)) {
            throw Exception("書き込んだCKVと読み出したCKVを比較 失敗")
        }

        println("0.5次発行　正常終了");
    }

    /*
      カードの正当性チェック
      戻り値：
      カードが正当：0
      カードが不正：-1
      カード接続失敗：-2
    */
    fun checkMac():Int
    {
        // RC用に1～100の擬似乱数を16個生成
        val rc = ByteArray(16) {
            (1..100).random().toByte()
        }

        val rc1 = rc.copyOfRange(0, 8)
        val rc2 = rc.copyOfRange(8, 16)

        //RCを書き込む
        writeWithoutEncryption(FELICA_SERVICE_RW, ADDRESS_RC, rc)

        //IDとMAC_Aを読み出す
        val macBlock = readIdWithMacA()

        val blockLow = macBlock.copyOfRange(12, 20)
        val blockHigh = macBlock.copyOfRange(20, 28)

        val cardMacA = macBlock.copyOfRange(28, 36)

        //MACの比較
        if (compareMac(cardMacA, rc1, rc2, blockLow, blockHigh)) {
            return 0;
        } else {
            return -1;
        }
    }

    fun readWithoutEncryption(addr:Int, serviceCode:Int):ByteArray

    {
        val bout = ByteArrayOutputStream(100)
        bout.write(0) // データ長バイトのダミー
        bout.write(0x06) // コマンドコード
        bout.write(targetIDm) // IDm 8byte
        bout.write(1) // サービス数の長さ(以下２バイトがこの数分繰り返す)

        // サービスコードの指定はリトルエンディアンなので、下位バイトから指定します。
        bout.write(serviceCode and 0xFF) // サービスコード下位バイト
        bout.write(serviceCode shr 8 and 0xFF) // サービスコード上位バイト
        bout.write(1) // ブロック数(1ブロックにすることで単純化する)

        // ブロック番号の指定
        bout.write(0x00) // ブロックエレメント [長さ(1=2byte,0=1byte 1bit] [アクセスモード 3bit] [SERVICEコードリスト順番 4bit]
        bout.write(addr and 0xFF) // ブロックエレメント下位バイト
        bout.write(addr shr 8 and 0xFF) // ブロックエレメント上位バイト
        val msg = bout.toByteArray()
        msg[0] = msg.size.toByte() // 先頭１バイトはデータ長

        // コマンドを送信して結果を取得
        val res = nfc!!.transceive(msg)
        val reslen = res.size

        // レスポンスのチェック
        if (reslen < 12) {
            throw IOException("Response length error")
        }
        if (res[0] < 12) {
            throw IOException("Response length information invalid")
        }
        if (res[1] != (0x07).toByte()) //readWithoutEncryption
        {
            throw IOException("Response code error")
        }
        if (res[10] != (0x00).toByte()) {
            val str = "Felica cards respond Error : Code " + String.format(
                    "%02X,%02X",
                    res[10],
                    res[11]
            )
            throw IOException(str)
        }
        val data = ByteArray(16)
        for (i in 0..15)data[i] = res[13 + i]
        return data
    }

    fun writeWithoutEncryption(serviceCode:Int, addr:Int, data:ByteArray) {
        val bout = ByteArrayOutputStream(100)
        bout.write(0) // データ長バイトのダミー
        bout.write(0x08) // コマンドコード
        bout.write(targetIDm) // IDm 8byte
        bout.write(1) // サービス数の長さ(以下２バイトがこの数分繰り返す)

        // サービスコードの指定はリトルエンディアンなので、下位バイトから指定します。
        bout.write(serviceCode and 0xFF) // サービスコード下位バイト
        bout.write(serviceCode shr 8 and 0xFF) // サービスコード上位バイト
        bout.write(1) // ブロック数(1ブロックにすることで単純化する)

        // ブロック番号の指定
        bout.write(0x00) // ブロックエレメント [長さ(1=2byte,0=1byte 1bit] [アクセスモード 3bit] [SERVICEコードリスト順番 4bit]
        bout.write(addr and 0xFF) // ブロックエレメント下位バイト
        bout.write(addr shr 8 and 0xFF) // ブロックエレメント上位バイト

        //データ書き込み
        require(data.size == 16) {
            "Data length invalid"
        }
        for (i in 0..15){
            bout.write(data[i].toInt())
        }
        val msg:ByteArray = bout.toByteArray()
        msg[0] = msg.size.toByte() // 先頭１バイトはデータ長

        // コマンドを送信して結果を取得
        val res:ByteArray = nfc.transceive(msg)
        val reslen = res.size

        // レスポンスのチェック
        if (reslen < 12) {
            throw IOException("Response length error")
        }
        if (res[0] < 12) {
            throw IOException("Response length information invalid")
        }
        if (res[1] != (0x09).toByte()) //writeWithoutEncryption
        {
            throw IOException("Response code error")
        }
        if (res[10] != 0x00.toByte()) {
            val str = "Felica cards respond Error : Code " + String.format(
                    "%02X,%02X",
                    res[10],
                    res[11]
            )
            throw IOException(str)
        }
        return
    }

    fun readIdWithMacA():ByteArray

    {
        val serviceCode:Int = 0x000b

        val bout = ByteArrayOutputStream(100)
        bout.write(0) // データ長バイトのダミー
        bout.write(0x06) // コマンドコード
        bout.write(targetIDm) // IDm 8byte
        bout.write(1) // サービス数の長さ(以下２バイトがこの数分繰り返す)

        // サービスコードの指定はリトルエンディアンなので、下位バイトから指定します。
        bout.write(serviceCode and 0xFF) // サービスコード下位バイト
        bout.write(serviceCode shr 8 and 0xFF) // サービスコード上位バイト
        bout.write(2) // ブロック数

        // ブロック番号の指定
        bout.write(0x80)
        bout.write(0x82)
        bout.write(0x80)
        bout.write(0x91)
        val msg = bout.toByteArray()
        msg[0] = msg.size.toByte() // 先頭１バイトはデータ長

        // コマンドを送信して結果を取得
        val res = nfc!!.transceive(msg)
        val reslen = res.size

        // レスポンスのチェック
        if (reslen != 45) {
            throw IOException("Response length error")
        }
        if (res[0] != 45. toByte()){
        throw IOException("Response length information invalid")
    }
        val data = ByteArray(44)
        for (i in 1..44)data[i - 1] = res[i]
        println("readIdWithMacA: " + data.toHexString())
        return data
    }


    /*
      MACの比較
    */
    fun compareMac(cardMacA:ByteArray, rc1:ByteArray, rc2:ByteArray, blockLow:ByteArray, blockHigh:ByteArray):Boolean

    {
        val zero = ByteArray(8)

        val(ck1, ck2) = getCK()

        val rc1_r = rc1.reversedArray()
        val rc2_r = rc2.reversedArray()
        val ck1_r = ck1.reversedArray()
        val ck2_r = ck2.reversedArray()

        //SK1を生成
        val iv1 = tripleDes2KeyCbc(rc1_r, zero, ck1_r, ck2_r);
        val sk1 = iv1.copyOf()
        // skの定義的にはバイトオーダー反転が必要だが、sk使用時にも反転で使うため意味ないのでスキップする
        //  swapByteOrder(SK1);

        //SK2を生成
        val iv2 = tripleDes2KeyCbc(rc2_r, iv1, ck1_r, ck2_r);
        val sk2 = iv2.copyOf()
        // skの定義的にはバイトオーダー反転が必要だが、sk使用時にも反転で使うため意味ないのでスキップする
        //  swapByteOrder(SK2);

        //MAC_Aを生成
        val blockInfo = byteArrayOfInts((ADDRESS_ID and 0xFF), 0, (ADDRESS_MAC_A and 0xFF),
        0, 0xFF, 0xFF, 0xFF, 0xFF)

        val blockInfo_r = blockInfo.reversedArray()
        val blockLow_r = blockLow.reversedArray()
        val blockHigh_r = blockHigh.reversedArray()

        val out1 = tripleDes2KeyCbc(blockInfo_r, rc1_r, sk1, sk2)
        val out2 = tripleDes2KeyCbc(blockLow_r, out1, sk1, sk2)
        val calcMacA = tripleDes2KeyCbc(blockHigh_r, out2, sk1, sk2)

        val calcMacA_r = calcMacA.reversedArray()

        println("生成したMAC_A [" + calcMacA_r.toHexString() + "]")

        //内部認証（カードのMAC_Aと生成したMAC_Aを比較）
        println("カードのMAC_A [" + cardMacA.toHexString() + "]")
        if (calcMacA_r.contentEquals(cardMacA)) {
            return true
        } else {
            println("MAC不一致")
            return false
        }
    }

    fun tripleDes2KeyCbc(input:ByteArray, iv:ByteArray, key1:ByteArray, key2:ByteArray):ByteArray
    {
        return tripleDes3KeyCbc(input, iv, key1, key2, key1)
    }

    fun tripleDes3KeyCbc(input:ByteArray, iv:ByteArray, key1:ByteArray, key2:ByteArray, key3:ByteArray):ByteArray
    {
        // ---- Use specified 3DES key and IV from other source --------------
        val tdesKeyData:ByteArray = key1 + key2 + key3
        //val c3des: Cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")
        val c3des:Cipher = Cipher.getInstance("DESede/CBC/NoPadding")
        val myKey = SecretKeySpec(tdesKeyData, "DESede")
        val ivspec = IvParameterSpec(iv)
        c3des.init(Cipher.ENCRYPT_MODE, myKey, ivspec)
        return c3des.doFinal(input)
    }

    fun getCK():Pair<ByteArray, ByteArray>

    {
        val ck = generatePersonalizedCK();
        val ck1 = ck.copyOfRange(0, 8)
        val ck2 = ck.copyOfRange(8, 16)
        return ck1 to ck2
    }

    /*
      個別化カード鍵の作成
    */
    fun generatePersonalizedCK():ByteArray
    {
        //IDブロックの値を読み出す
        val id = readWithoutEncryption(ADDRESS_ID, FELICA_SERVICE_RW)

        println("IDブロック　　 [" + id.toHexString() + "]")

        val zero = ByteArray(8)

        //0と個別化マスター鍵で3DES→結果L
        val k1 = tripleDes3KeyCbc(zero, zero, mk1, mk2, mk3)

//        println("k1: "+k1.toHexString())

        // L の最上位ビットが 0 の場合、L を左に 1 ビットシフトした結果を K1 とします。
        // また、L の最上位ビットが 1 の場合、L を左に 1 ビットシフトした結果と 000000000000001Bh (8 バイト)  との排他的論理和を K1 とします。
        // なお、「L を左に 1 ビットシフトする」とは、L を 2 倍して最上位ビットを捨てることを意味します。
        var msb = false
        for (i in 7 downTo 0){
            val bak = msb
            msb = (k1[i] and 0x80.toByte()) != 0.toByte()
            //msb = (k1[i].toUByte() and 0x80.toUByte()) != 0.toUByte()
    //            println("aa"+(k1[i] and 0x80.toByte()))
    //            println("bb"+(k1[i].toUByte() and 0x80.toUByte()))
    //            println("msb: "+msb)
            k1[i] = (k1[i].toInt() shl 1).toByte(); // Byteにはshlないので仕方なく一旦Intで演算してByteへ。上の行も無理にkotlin.experimental.and使わないでIntにしたほうがいいかもしれない。。

            if (bak) {
                //下のバイトからのcarry
                k1[i] = k1[i] or 0x01;
            }
        }

        //Lの最上位ビットが1の場合、最下位バイトと0x1bをXORする
        if (msb) {
            k1[7] = k1[7] xor 0x1b;
        }

//        println("k1_mod: "+k1.toHexString())

        val id1 = id.copyOfRange(0, 8)
        val id2 = id.copyOfRange(8, 16).mapIndexed {i, it -> it xor k1[i]}.toByteArray()
//        println("id1: "+id1.toHexString())
//        println("id2: "+id2.toHexString())

        //M1を平文、Kを鍵として3DES→結果C1
        val c1 = tripleDes3KeyCbc(id1, zero, mk1, mk2, mk3)
//        println("c1: "+c1.toHexString())

        //C1とM2をXORした結果を平文、Kを鍵として3DES→結果T
        val t1 = tripleDes3KeyCbc(id2, c1, mk1, mk2, mk3)

        //M1の最上位ビットを反転→M1'
        id1[0] = id1[0] xor(0x80.toByte())

        //M1'を平文、Kを鍵として3DES→結果C1'
        val c1_1 = tripleDes3KeyCbc(id1, zero, mk1, mk2, mk3)

        // (C1' xor M2)を平文、Kを鍵として3DES→結果T'
        val t1_1 = tripleDes3KeyCbc(id2, c1_1, mk1, mk2, mk3)

        //Tを上位8byte、T'を下位8byte→結果C→個別化カード鍵
        val ck = ByteArray(16)
        t1.copyInto(ck, 0, 0, 8)
        t1_1.copyInto(ck, 8, 0, 8)

        print("個別化カード鍵 [" + ck.toHexString() + "]")

        return ck
    }
}



