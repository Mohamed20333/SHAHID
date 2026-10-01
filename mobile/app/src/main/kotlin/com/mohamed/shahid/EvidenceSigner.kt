package com.mohamed.shahid

import java.time.Instant
import java.util.UUID

class EvidenceSigner(private val identity:CryptoIdentity){
 fun witnessPayload(sessionId:String,observerDeviceId:String,observedDeviceId:String,rssi:Int,nonce:String,timestamp:String,observationType:String="ble_proximity",protocolVersion:String="1") =
   listOf("nonce=$nonce","observationType=$observationType","observedDeviceId=$observedDeviceId","observerDeviceId=$observerDeviceId","protocolVersion=$protocolVersion","rssi=$rssi","sessionId=$sessionId","timestamp=$timestamp").joinToString("&")
 fun signWitness(sessionId:String,observerDeviceId:String,observedDeviceId:String,rssi:Int,nonce:String,timestamp:String):String =
   identity.sign(witnessPayload(sessionId,observerDeviceId,observedDeviceId,rssi,nonce,timestamp))
 fun freshNonce()=UUID.randomUUID().toString()+UUID.randomUUID().toString()
 fun now()=Instant.now().toString()
}