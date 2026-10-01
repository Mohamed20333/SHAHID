package com.mohamed.shahid

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

class EvidenceService:Service(){
 private val executor=Executors.newSingleThreadExecutor()
 private var ble:BleEvidence?=null
 private var token:String?=null
 private var sessionId:String?=null
 private var deviceId:String?=null
 private var ephemeralId:String?=null
 private val sequence=AtomicLong(0)

 override fun onCreate(){
  super.onCreate()
  val nm=getSystemService(NotificationManager::class.java)
  nm.createNotificationChannel(NotificationChannel("evidence","SHAHID Evidence",NotificationManager.IMPORTANCE_LOW))
  startForeground(7,Notification.Builder(this,"evidence").setContentTitle("SHAHID evidence collection").setContentText("BLE proximity evidence is active").setSmallIcon(android.R.drawable.ic_menu_info_details).build())
 }
 override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int{
  token=intent?.getStringExtra("token");sessionId=intent?.getStringExtra("sessionId");deviceId=intent?.getStringExtra("deviceId");ephemeralId=intent?.getStringExtra("ephemeralId")
  val t=token;val s=sessionId;val d=deviceId;val e=ephemeralId
  if(t==null||s==null||d==null||e==null){stopSelf();return START_NOT_STICKY}
  val identity=CryptoIdentity();val signer=EvidenceSigner(identity);val baseUrl=intent?.getStringExtra("baseUrl") ?: "http://10.0.2.2:8080";val api=ApiClient(baseUrl)
  ble=BleEvidence(this).also{b->
    b.startAdvertising(e)
    b.startScan{observedEphemeral,rssi->
      executor.execute{
        try{
          val challenge=api.witnessChallenge(t,s,d)
          val nonce=challenge.getString("nonce")
          val ts=signer.now()
          val signature=signer.signWitness(s,d,observedEphemeral,rssi,nonce,ts)
          api.witness(t,s,d,rssi,challenge.getString("id"),signature,ts,observedEphemeral)
        }catch(_:Exception){}
      }
    }
  }
  scheduleHeartbeat(api,t,s,d,signer)
  return START_STICKY
 }
 private fun scheduleHeartbeat(api:ApiClient,t:String,s:String,d:String,signer:EvidenceSigner){
   executor.execute{
     var n=0L
     while(!Thread.currentThread().isInterrupted){
       try{
         val ts=signer.now();api.heartbeat(t,s,d,n,signer.signHeartbeat(s,d,n,ts),ts);n++
         Thread.sleep(30000)
       }catch(_:Exception){Thread.sleep(30000)}
     }
   }
 }
 override fun onDestroy(){ble?.stopScan();ble?.stopAdvertising();executor.shutdownNow();super.onDestroy()}
 override fun onBind(intent:Intent?):IBinder?=null
}
