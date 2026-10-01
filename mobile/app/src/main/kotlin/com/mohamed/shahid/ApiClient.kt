package com.mohamed.shahid

import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

class ApiClient(private val baseUrl:String){
 data class Challenge(val id:String,val nonce:String,val purpose:String,val sessionId:String?)
 private fun request(path:String,method:String,token:String?,json:JSONObject,deviceId:String?=null):JSONObject{
  val c=URL(baseUrl.trimEnd('/')+path).openConnection() as HttpURLConnection
  c.requestMethod=method;c.connectTimeout=10000;c.readTimeout=15000;c.doOutput=method!="GET"
  c.setRequestProperty("Content-Type","application/json")
  if(token!=null)c.setRequestProperty("Authorization","Bearer $token")
  if(deviceId!=null)c.setRequestProperty("X-Device-ID",deviceId)
  if(c.doOutput) c.outputStream.use{it.write(json.toString().toByteArray(Charsets.UTF_8))}
  val stream=if(c.responseCode<400)c.inputStream else c.errorStream
  val text=stream.bufferedReader().use{it.readText()}
  if(c.responseCode>=400)throw IllegalStateException(text)
  return if(text.isBlank()) JSONObject() else JSONObject(text)
 }
 fun login(email:String,password:String)=request("/auth/login","POST",null,JSONObject().put("email",email).put("password",password))
 fun me(token:String)=request("/me","GET",token,JSONObject())
 fun studentSessions(token:String)=request("/student/sessions","GET",token,JSONObject())
 fun enrollmentChallenge(token:String,publicKey:String,keyId:String)=request("/devices/enroll/challenge","POST",token,JSONObject().put("publicKey",publicKey).put("keyId",keyId))
 fun completeEnrollment(token:String,challengeId:String,signature:String)=request("/devices/enroll/complete","POST",token,JSONObject().put("challengeId",challengeId).put("signature",signature))
 fun sessionChallenge(token:String,deviceId:String,sessionId:String)=request("/devices/proof-challenge","POST",token,JSONObject().put("deviceId",deviceId).put("sessionId",sessionId))
 fun checkIn(token:String,sessionId:String,deviceId:String,challengeId:String,signature:String,timestamp:String)=request("/sessions/$sessionId/check-in","POST",token,JSONObject().put("deviceId",deviceId).put("challengeId",challengeId).put("signature",signature).put("timestamp",timestamp))
 fun beacon(token:String,sessionId:String,deviceId:String)=request("/sessions/$sessionId/beacon","POST",token,JSONObject().put("deviceId",deviceId))
 fun witnessChallenge(token:String,sessionId:String,observerDeviceId:String)=request("/sessions/$sessionId/witness-challenge","POST",token,JSONObject(),observerDeviceId)
 fun witness(token:String,sessionId:String,observerDeviceId:String,rssi:Int,challengeId:String,signature:String,timestamp:String,ephemeralId:String)=request("/sessions/$sessionId/witnesses","POST",token,JSONObject().put("rssi",rssi).put("challengeId",challengeId).put("signature",signature).put("timestamp",timestamp).put("observationType","ble_proximity").put("protocolVersion","1").put("ephemeralId",ephemeralId),observerDeviceId)
 fun heartbeat(token:String,sessionId:String,deviceId:String,sequence:Long,signature:String,timestamp:String)=request("/sessions/$sessionId/heartbeat","POST",token,JSONObject().put("deviceId",deviceId).put("sequence",sequence).put("signature",signature).put("timestamp",timestamp))
}
