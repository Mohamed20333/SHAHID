package com.mohamed.shahid
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.MessageDigest
import android.util.Base64

class CryptoIdentity {
 private val alias="shahid-device-ed25519"
 private val store=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
 fun ensure():KeyPair {
   if(store.containsAlias(alias)){val e=store.getEntry(alias,null) as KeyStore.PrivateKeyEntry;return KeyPair(e.certificate.publicKey,e.privateKey)}
   val gen=KeyPairGenerator.getInstance("Ed25519","AndroidKeyStore")
   gen.initialize(KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_NONE).build())
   return gen.generateKeyPair()
 }
 fun publicKeyPem():String { val p=ensure().public.encoded;return "-----BEGIN PUBLIC KEY-----\n"+Base64.encodeToString(p,Base64.NO_WRAP)+"\n-----END PUBLIC KEY-----" }
 fun keyId():String = MessageDigest.getInstance("SHA-256").digest(ensure().public.encoded).joinToString("") { "%02x".format(it) }.take(32)
 fun sign(message:String):String { val s=Signature.getInstance("Ed25519");s.initSign(ensure().private);s.update(message.toByteArray(Charsets.UTF_8));return Base64.encodeToString(s.sign(),Base64.NO_WRAP).replace("+","-").replace("/","_").replace("=","") }
}