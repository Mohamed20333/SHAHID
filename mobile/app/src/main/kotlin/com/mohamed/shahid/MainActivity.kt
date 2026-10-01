package com.mohamed.shahid
import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity

class MainActivity:AppCompatActivity(){
 private val identity=CryptoIdentity()
 override fun onCreate(savedInstanceState:Bundle?){super.onCreate(savedInstanceState)
   val layout=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;setPadding(32,32,32,32)}
   val title=TextView(this).apply{text="SHAHID";textSize=30f}
   val subtitle=TextView(this).apply{text="Attendance Integrity";textSize=16f}
   val identityButton=Button(this).apply{text="Create / inspect device identity"}
   val sessionButton=Button(this).apply{text="Start evidence collection"}
   val status=TextView(this).apply{text="No session active";setPadding(0,24,0,24)}
   identityButton.setOnClickListener{try{val p=identity.ensure();status.text="Ed25519 identity ready\nKey ID: ${identity.keyId()}\nPrivate key remains in Android Keystore."}catch(e:Exception){status.text="Device key unavailable: ${e.message}"}}
   sessionButton.setOnClickListener{if(Build.VERSION.SDK_INT>=31)requestPermissions(arrayOf(Manifest.permission.BLUETOOTH_SCAN,Manifest.permission.BLUETOOTH_ADVERTISE,Manifest.permission.BLUETOOTH_CONNECT),44);startForegroundService(Intent(this,EvidenceService::class.java));status.text="Evidence service requested. Android may restrict background execution."}
   layout.addView(title);layout.addView(subtitle);layout.addView(status);layout.addView(identityButton);layout.addView(sessionButton);setContentView(layout)
 }
}