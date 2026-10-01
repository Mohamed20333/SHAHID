package com.mohamed.shahid
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder

class EvidenceService:Service(){
 override fun onCreate(){super.onCreate();val nm=getSystemService(NotificationManager::class.java);nm.createNotificationChannel(NotificationChannel("evidence","SHAHID Evidence",NotificationManager.IMPORTANCE_LOW));startForeground(7,Notification.Builder(this,"evidence").setContentTitle("SHAHID evidence collection").setContentText("BLE evidence is active for the current session").setSmallIcon(android.R.drawable.ic_menu_info_details).build())}
 override fun onStartCommand(intent:Intent?,flags:Int,startId:Int)=START_NOT_STICKY
 override fun onBind(intent:Intent?):IBinder?=null
}