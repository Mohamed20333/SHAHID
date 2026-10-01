package com.mohamed.shahid

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import java.util.concurrent.Executors

class MainActivity:AppCompatActivity(){
 private val identity=CryptoIdentity()
 private val executor=Executors.newSingleThreadExecutor()
 private val prefs by lazy{getSharedPreferences("shahid",MODE_PRIVATE)}
 private lateinit var api:ApiClient
 private lateinit var status:TextView
 private lateinit var sessionsBox:LinearLayout

 override fun onCreate(savedInstanceState:Bundle?){super.onCreate(savedInstanceState);buildUi()}

 private fun buildUi(){
  val layout=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;setPadding(32,32,32,32)}
  val title=TextView(this).apply{text="SHAHID";textSize=30f}
  val subtitle=TextView(this).apply{text="Attendance Integrity · Android Evidence Client";textSize=16f}
  val apiUrl=EditText(this).apply{setText(prefs.getString("apiUrl","http://10.0.2.2:8080"));hint="API URL"}
  val email=EditText(this).apply{hint="Email";inputType=33}
  val password=EditText(this).apply{hint="Password";inputType=129}
  val login=Button(this).apply{text="Sign in"}
  status=TextView(this).apply{text="Not signed in";setPadding(0,20,0,20)}
  val identityButton=Button(this).apply{text="Enroll / inspect device identity";isEnabled=false}
  val refresh=Button(this).apply{text="Refresh active sessions";isEnabled=false}
  sessionsBox=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
  login.setOnClickListener{
   prefs.edit().putString("apiUrl",apiUrl.text.toString().trim().trimEnd('/')).apply()
   api=ApiClient(prefs.getString("apiUrl","http://10.0.2.2:8080")!!)
   runAsync{
    try{
     val d=api.login(email.text.toString().trim(),password.text.toString())
     prefs.edit().putString("token",d.getString("accessToken")).putString("role",d.getString("role")).apply()
     val me=api.me(d.getString("accessToken"))
     runOnUiThread{status.text="Signed in as "+me.getString("full_name")+" · "+me.getString("role");identityButton.isEnabled=true;refresh.isEnabled=me.getString("role")=="student";refreshSessions()}
    }catch(e:Exception){showError(e)}
   }
  }
  identityButton.setOnClickListener{runAsync{try{ensureDevice();runOnUiThread{status.text="Device identity enrolled. Key remains in Android Keystore."}}catch(e:Exception){showError(e)}}}
  refresh.setOnClickListener{refreshSessions()}
  layout.addView(title);layout.addView(subtitle);layout.addView(apiUrl);layout.addView(email);layout.addView(password);layout.addView(login);layout.addView(status);layout.addView(identityButton);layout.addView(refresh);layout.addView(sessionsBox)
  setContentView(layout)
 }

 private fun refreshSessions(){
  val token=prefs.getString("token",null)?:return
  runAsync{try{val arr=api.studentSessions(token);runOnUiThread{renderSessions(arr)}}catch(e:Exception){showError(e)}}
 }

 private fun renderSessions(arr:JSONArray){
  sessionsBox.removeAllViews()
  if(arr.length()==0){sessionsBox.addView(TextView(this).apply{text="No active sessions."});return}
  for(i in 0 until arr.length()){
   val s=arr.getJSONObject(i);val id=s.getString("id")
   val label=s.optString("code","Session")+" · "+s.optString("title","")+" — "+(if(s.optBoolean("checked_in"))"Checked in" else "Check in & start evidence")
   val b=Button(this).apply{text=label}
   b.setOnClickListener{startAttendance(id,b)}
   sessionsBox.addView(b)
  }
 }

 private fun ensureDevice():String{
  val existing=prefs.getString("deviceId",null);if(existing!=null)return existing
  val token=prefs.getString("token",null)?:error("Sign in first")
  val keyId=identity.keyId();val challenge=api.enrollmentChallenge(token,identity.publicKeyPem(),keyId)
  val signer=EvidenceSigner(identity)
  val signature=identity.sign(signer.enrollmentPayload(challenge.getString("challengeId"),challenge.getString("nonce"),"device_enrollment",keyId))
  val result=api.completeEnrollment(token,challenge.getString("challengeId"),signature)
  val deviceId=result.getString("deviceId");prefs.edit().putString("deviceId",deviceId).apply();return deviceId
 }

 private fun startAttendance(sessionId:String,button:Button){
  val token=prefs.getString("token",null)?:return
  runAsync{
   try{
    val deviceId=ensureDevice();val signer=EvidenceSigner(identity)
    val challenge=api.sessionChallenge(token,deviceId,sessionId);val ts=signer.now()
    val sig=signer.signCheckIn(challenge.getString("challengeId"),challenge.getString("nonce"),challenge.getString("purpose"),sessionId,deviceId,ts)
    api.checkIn(token,sessionId,deviceId,challenge.getString("challengeId"),sig,ts)
    val beacon=api.beacon(token,sessionId,deviceId)
    if(!ensureBluetooth()){runOnUiThread{status.text="Enable Bluetooth and grant Nearby Devices permission, then press the session button again."};return@runAsync}
    val service=Intent(this,EvidenceService::class.java).apply{
      putExtra("token",token);putExtra("sessionId",sessionId);putExtra("deviceId",deviceId)
      putExtra("ephemeralId",beacon.getString("ephemeralId"));putExtra("baseUrl",prefs.getString("apiUrl","http://10.0.2.2:8080"))
    }
    if(Build.VERSION.SDK_INT>=26)startForegroundService(service) else startService(service)
    runOnUiThread{button.text="Evidence active";button.isEnabled=false;status.text="Checked in. BLE advertising + scanning + signed witnesses + heartbeats are active."}
   }catch(e:Exception){showError(e)}
  }
 }

 private fun ensureBluetooth():Boolean{
  if(!hasBlePermissions()){requestBlePermissions();return false}
  val adapter=getSystemService(BLUETOOTH_SERVICE) as BluetoothAdapter
  if(!adapter.isEnabled){startActivityForResult(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE),77);return false}
  if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED){requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS),78);return false}
  return true
 }

 private fun hasBlePermissions():Boolean{
  return if(Build.VERSION.SDK_INT>=31){
   checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN)==PackageManager.PERMISSION_GRANTED &&
   checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE)==PackageManager.PERMISSION_GRANTED &&
   checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)==PackageManager.PERMISSION_GRANTED
  }else checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)==PackageManager.PERMISSION_GRANTED
 }

 private fun requestBlePermissions(){
  if(Build.VERSION.SDK_INT>=31)requestPermissions(arrayOf(Manifest.permission.BLUETOOTH_SCAN,Manifest.permission.BLUETOOTH_ADVERTISE,Manifest.permission.BLUETOOTH_CONNECT),44)
  else requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION),45)
 }

 private fun runAsync(block:()->Unit){executor.execute(block)}
 private fun showError(e:Exception){runOnUiThread{status.text="Error: "+(e.message ?: "request failed")}}
 override fun onDestroy(){executor.shutdownNow();super.onDestroy()}
}
