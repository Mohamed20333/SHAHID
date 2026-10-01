package com.mohamed.shahid

import java.time.Instant

class EvidenceSigner(private val identity:CryptoIdentity){
 private fun canonical(fields:Map<String,Any?>)=fields.toSortedMap().entries.joinToString("&"){entry->entry.key+"="+(entry.value ?: "")}
 fun checkInPayload(challengeId:String,nonce:String,purpose:String,sessionId:String,deviceId:String,timestamp:String)=canonical(mapOf("challengeId" to challengeId,"deviceId" to deviceId,"nonce" to nonce,"purpose" to purpose,"sessionId" to sessionId,"timestamp" to timestamp))
 fun signCheckIn(challengeId:String,nonce:String,purpose:String,sessionId:String,deviceId:String,timestamp:String)=identity.sign(checkInPayload(challengeId,nonce,purpose,sessionId,deviceId,timestamp))
 fun enrollmentPayload(challengeId:String,nonce:String,purpose:String,keyId:String)=canonical(mapOf("challengeId" to challengeId,"keyId" to keyId,"nonce" to nonce,"purpose" to purpose))
 fun signEnrollment(challengeId:String,nonce:String,purpose:String,keyId:String)=identity.sign(enrollmentPayload(challengeId,nonce,purpose,keyId))
 fun witnessPayload(sessionId:String,observerDeviceId:String,observedDeviceId:String,rssi:Int,nonce:String,timestamp:String,observationType:String="ble_proximity",protocolVersion:String="1")=canonical(mapOf("nonce" to nonce,"observationType" to observationType,"observedDeviceId" to observedDeviceId,"observerDeviceId" to observerDeviceId,"protocolVersion" to protocolVersion,"rssi" to rssi,"sessionId" to sessionId,"timestamp" to timestamp))
 fun signWitness(sessionId:String,observerDeviceId:String,observedDeviceId:String,rssi:Int,nonce:String,timestamp:String)=identity.sign(witnessPayload(sessionId,observerDeviceId,observedDeviceId,rssi,nonce,timestamp))
 fun heartbeatPayload(sessionId:String,deviceId:String,sequence:Long,timestamp:String)=canonical(mapOf("deviceId" to deviceId,"sequence" to sequence,"sessionId" to sessionId,"timestamp" to timestamp))
 fun signHeartbeat(sessionId:String,deviceId:String,sequence:Long,timestamp:String)=identity.sign(heartbeatPayload(sessionId,deviceId,sequence,timestamp))
 fun now()=Instant.now().toString()
}
