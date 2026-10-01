package com.mohamed.shahid
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import java.util.UUID

class BleEvidence(private val context:Context){
 private val serviceUuid=ParcelUuid(UUID.fromString("7b5a2d0e-0e22-4f54-9b42-9dbab0f9a001"))
 private val adapter=(context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
 private var scanner:BluetoothLeScanner?=null
 private var callback:ScanCallback?=null
 private var advertiser:BluetoothLeAdvertiser?=null
 private var advertiseCallback:AdvertiseCallback?=null
 fun startScan(onObservation:(String,Int)->Unit){
   scanner=adapter.bluetoothLeScanner
   callback=object:ScanCallback(){
     override fun onScanResult(type:Int,result:ScanResult){
       result.scanRecord?.serviceUuids?.firstOrNull{it==serviceUuid}?.let{onObservation(result.device.address,result.rssi)}
     }
     override fun onScanFailed(errorCode:Int){}
   }
   scanner?.startScan(callback)
 }
 fun startAdvertising(ephemeralId:ByteArray){
   advertiser=adapter.bluetoothLeAdvertiser ?: return
   val settings=AdvertiseSettings.Builder().setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER).setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_LOW).setConnectable(false).build()
   val data=AdvertiseData.Builder().setIncludeDeviceName(false).addServiceUuid(serviceUuid).addServiceData(serviceUuid,ephemeralId.copyOf(minOf(16,ephemeralId.size))).build()
   advertiseCallback=object:AdvertiseCallback(){}
   advertiser?.startAdvertising(settings,data,advertiseCallback)
 }
 fun stopAdvertising(){advertiseCallback?.let{advertiser?.stopAdvertising(it)};advertiseCallback=null}
 fun stopScan(){callback?.let{scanner?.stopScan(it)};callback=null}
}