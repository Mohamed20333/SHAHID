package com.mohamed.shahid

import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

class ApiClient(private val baseUrl:String){
 data class Challenge(val id:String,val nonce:String,val purpose:String,val sessionId:String?)
 private fun request(path:String,method:String,token:String?,json:JSONObject):JSONObject{
  val c=URL(baseUrl+path).openConnection() as HttpURLConnection
  c.requestMethod=method;c.connectTimeout=10000;c.readTimeout=15000;c.doOutput=true
  c.setRequestProperty("Content-Type","application/json")
  if(token!=null)c.setRequestProperty("Authorization","Bearer $token")
  c.outputStream.use{it.write(json.toString().toByteArray())}
  val stream=if(c.responseCode<400)c.inputStream else c.errorStream
  val text=stream.bufferedReader().use{it.readText()}
  if(c.responseCode>=400)throw IllegalStateException(text)
  return JSONObject(text)
 }
 fun enrollmentChallenge(token:String,publicKey:String,keyId:String)=request("/devices/enroll/challenge","POST",token,JSONObject().put("publicKey",publicKey).put("keyId",keyId))
 fun completeEnrollment(token:String,challengeId:String,signature:String)=request("/devices/enroll/complete","POST",token,JSONObject().put("challengeId",challengeId).put("signature",signature))
 fun sessionChallenge(token:String,deviceId:String,sessionId:String)=request("/devices/proof-challenge","POST",token,JSONObject().put("deviceId",deviceId).put("sessionId",sessionId))
 fun checkIn(token:String,sessionId:String,deviceId:String,challengeId:String,signature:String,timestamp:String)=request("/sessions/$sessionId/check-in","POST",token,JSONObject().put("deviceId",deviceId).put("challengeId",challengeId).put("signature",signature).put("timestamp",timestamp))
 fun witness(token:String,sessionId:String,observerDeviceId:String,observedDeviceId:String,rssi:Int,nonce:String,signature:String,timestamp:String,ephemeralId:String)=request("/sessions/$sessionId/witnesses","POST",token,JSONObject().put("observedDeviceId",observedDeviceId).put("rssi",rssi).put("nonce",nonce).put("signature",signature).put("timestamp",timestamp).put("observationType","ble_proximity").put("protocolVersion","1").put("ephemeralId",ephemeralId))
}