package com.mohamed.shahid
import android.bluetooth.BluetoothManager
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import java.util.UUID

class BleEvidence(private val context:Context){
 private val serviceUuid=ParcelUuid(UUID.fromString("7b5a2d0e-0e22-4f54-9b42-9dbab0f9a001"))
 private val adapter=(context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
 private var scanner:BluetoothLeScanner?=null
 private var callback:ScanCallback?=null
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
 fun stopScan(){callback?.let{scanner?.stopScan(it)};callback=null}
}