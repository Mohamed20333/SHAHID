package com.mohamed.shahid

import android.bluetooth.BluetoothManager
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import android.util.Base64
import java.util.UUID

class BleEvidence(private val context:Context){
 private val serviceUuid=ParcelUuid(UUID.fromString("7b5a2d0e-0e22-4f54-9b42-9dbab0f9a001"))
 private val adapter=(context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
 private var scanner:BluetoothLeScanner?=null
 private var callback:ScanCallback?=null
 private var advertiser:BluetoothLeAdvertiser?=null
 private var advertiseCallback:AdvertiseCallback?=null

 fun startScan(onObservation:(String,Int)->Unit){
   scanner=adapter.bluetoothLeScanner ?: return
   callback=object:ScanCallback(){
     override fun onScanResult(type:Int,result:ScanResult){
       val raw=result.scanRecord?.getServiceData(serviceUuid) ?: return
       val ephemeral=Base64.encodeToString(raw,Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
       onObservation(ephemeral,result.rssi)
     }
     override fun onScanFailed(errorCode:Int){}
   }
   scanner?.startScan(callback)
 }
 fun startAdvertising(ephemeralId:String){
   advertiser=adapter.bluetoothLeAdvertiser ?: return
   val bytes=Base64.decode(ephemeralId,Base64.URL_SAFE or Base64.NO_WRAP)
   val settings=AdvertiseSettings.Builder().setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER).setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_LOW).setConnectable(false).build()
   val data=AdvertiseData.Builder().setIncludeDeviceName(false).addServiceUuid(serviceUuid).addServiceData(serviceUuid,bytes.copyOf(minOf(16,bytes.size))).build()
   advertiseCallback=object:AdvertiseCallback(){}
   advertiser?.startAdvertising(settings,data,advertiseCallback)
 }
 fun stopAdvertising(){advertiseCallback?.let{advertiser?.stopAdvertising(it)};advertiseCallback=null}
 fun stopScan(){callback?.let{scanner?.stopScan(it)};callback=null}
}
