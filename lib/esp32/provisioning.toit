// Copyright (C) 2022 Toitware ApS. All rights reserved.
// Use of this source code is governed by an MIT-style license that can be
// found in the lib/LICENSE file.

import ble
import bytes
import encoding.json
import protobuf.protobuf
import net.wifi

SERVICE_UUID ::= #[0x02, 0x1a, 0x90, 0x04, 0x03, 0x82, 0x4a, 0xea,
                   0xbf, 0xf4, 0x6b, 0x3f, 0x1c, 0x5a, 0xdf, 0xb4]

SECURITY0 := Security0

abstract class Security:
  abstract encrypt data/ByteArray -> ByteArray
  abstract decrypt data/ByteArray -> ByteArray
  abstract version -> int

class Security0 extends Security:
  encrypt data/ByteArray -> ByteArray:
    return data

  decrypt data/ByteArray -> ByteArray:
    return data
  
  version -> int:
    return 0

class BLECharacteristic:
  characteristic_/ble.LocalCharacteristic := ?
  desc_/string := ?

  static UUID_BASE_ ::= 0xff
  static PROPERTYS_ ::= ble.CHARACTERISTIC_PROPERTY_READ | ble.CHARACTERISTIC_PROPERTY_WRITE
  static PERMISSIONS_ ::= ble.CHARACTERISTIC_PERMISSION_READ | ble.CHARACTERISTIC_PERMISSION_WRITE
  static DESC_UUID_ ::= ble.BleUuid #[0x00, 0x00, 0x29, 0x01, 0x00, 0x00, 0x10, 0x00,
                                      0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb]

  constructor service/ble.LocalService service_uuid/ByteArray id/int .desc_/string:
    uuid := ByteArray service_uuid.size : service_uuid[it]
    uuid[2] = UUID_BASE_
    uuid[3] = id

    characteristic_ = service.add_characteristic
        ble.BleUuid uuid
        --properties=PROPERTYS_
        --permissions=PERMISSIONS_
    characteristic_.add_descriptor
        DESC_UUID_
        PROPERTYS_
        PERMISSIONS_
        desc_.to_byte_array
  
  write data/ByteArray:
    characteristic_.write data

  read -> ByteArray:
    return characteristic_.read

class BLEService:
  characteristics_/Map := ?

  static CHARACTERISTICS_ ::= [{"name":"prov-scan",    "id":0x50},
                               {"name":"prov-session", "id":0x51},
                               {"name":"prov-config",  "id":0x52},
                               {"name":"proto-ver",    "id":0x53},
                               {"name":"custom-data",  "id":0x54}]

  constructor uuid/ByteArray name/string:
    adapter := ble.Adapter
    peripheral := adapter.peripheral
    service := peripheral.add_service
        ble.BleUuid uuid

    characteristics_ = Map
    CHARACTERISTICS_.do:
      characteristics_[it["name"]] =
          BLECharacteristic
              service
              uuid
              it["id"]
              it["name"]

    service.deploy

    peripheral.start_advertise
      ble.AdvertisementData
          --name=name
          --service_classes=[ble.BleUuid uuid]
          --flags=ble.BLE_ADVERTISE_FLAGS_GENERAL_DISCOVERY |
                  ble.BLE_ADVERTISE_FLAGS_BREDR_UNSUPPORTED
      --interval=Duration --us=160000
      --connection_mode=ble.BLE_CONNECT_MODE_UNDIRECTIONAL
  
  operator [] name/string -> BLECharacteristic:
    return characteristics_[name]

class WiFiConfig:
  ssid/string := ""
  password/string := ""
  connect/bool := false

  constructor :

abstract class Process:
  abstract run data/ByteArray -> ByteArray

class SessionProcess extends Process:
  static SESSION_0_ ::= 10      /* type: message */
  static SESSION_0_MSG_  ::= 1  /* type: enum */
  static SESSION_0_REQ_  ::= 20 /* type: message */
  static SESSION_0_RESP_ ::= 21 /* type: message */

  run data/ByteArray -> ByteArray:
    msg_id := null
    resp := #[]

    r := protobuf.Reader data
    r.read_message:
      r.read_field SESSION_0_:
        r.read_message:
          r.read_field SESSION_0_REQ_:
            msg_id = SESSION_0_REQ_

    if msg_id == SESSION_0_REQ_:
      resp_msg := {SESSION_0_: {SESSION_0_MSG_: 1}}
      resp = protobuf_map_to_bytes --message=resp_msg

    return resp

class ScanProcess extends Process:
  static MSG_ ::= 1
  static MSG_REQ_START_   ::= 0
  static MSG_RESP_START_  ::= 1
  static MSG_REQ_STATUS_  ::= 2
  static MSG_RESP_STATUS_ ::= 3
  static MSG_REQ_RESULT_  ::= 4
  static MSG_RESP_RESULT_ ::= 5

  static REQ_START_ ::= 10
  static REQ_START_BLOCK_  ::= 1
  static REQ_START_PERIOD_ ::= 4

  static REQ_STATUS_ ::= 12

  static RESP_STATUS_ ::= 13
  static RESP_STATUS_FINISHED_ ::= 1
  static RESP_STATUS_COUNT_    ::= 2

  static REQ_RESULT_ ::= 14
  static REQ_RESULT_START_ ::= 1
  static REQ_RESULT_COUNT_ ::= 2

  static RESP_RESULT_ ::= 15
  static RESP_RESULT_ENTRIES_ ::= 1
  static RESP_RESULT_ENTRIES_SSID_    ::= 1
  static RESP_RESULT_ENTRIES_CHANNEL_ ::= 2
  static RESP_RESULT_ENTRIES_RSSI_    ::= 3
  static RESP_RESULT_ENTRIES_BSSID_   ::= 4
  static RESP_RESULT_ENTRIES_AUTH_    ::= 5

  static CHANNEL_NUM_ ::= 14
  ap_list_ := List
  report_count_ := 4
  block_ := true
  period_ := 120

  msg_offset_ := 0

  constructor :

  comp_ap_by_rssi_ a/Map b/Map -> int:
    a_rssi := a[wifi.SCAN_AP_RSSI]
    b_rssi := b[wifi.SCAN_AP_RSSI]
    if a_rssi < b_rssi:
      return 1
    else if a_rssi == b_rssi:
      return 0
    else:
      return -1

  scan_task_:
    channels := ByteArray CHANNEL_NUM_
    CHANNEL_NUM_.repeat: channels[it]=it + 1
    ap_list_ = wifi.scan
        channels
        --period_per_channel=period_
    ap_list_.sort --in_place=true:
      | a b | comp_ap_by_rssi_ a b

  scan_start_ r/protobuf.Reader -> ByteArray:
    r.read_message:
      r.read_field REQ_START_BLOCK_:
        block_ = r.read_primitive protobuf.PROTOBUF_TYPE_INT32
      r.read_field REQ_START_PERIOD_:
        period_ = r.read_primitive protobuf.PROTOBUF_TYPE_INT32

    msg_offset_ = 0
    scan_task_

    resp_msg := {
        MSG_: MSG_RESP_START_
    }
    resp := protobuf_map_to_bytes --message=resp_msg
    return resp
  
  scan_status_ -> ByteArray:
    buffer := bytes.Buffer
    w := protobuf.Writer buffer

    resp_msg := {
        MSG_: MSG_RESP_STATUS_,
        RESP_STATUS_: {
            RESP_STATUS_FINISHED_: 1,
            RESP_STATUS_COUNT_: ap_list_.size
        }
    }
    resp := protobuf_map_to_bytes --message=resp_msg
    return resp
  
  scan_result_ r/protobuf.Reader -> ByteArray:
    r.read_message:
        r.read_field REQ_RESULT_COUNT_:
          report_count_ = r.read_primitive protobuf.PROTOBUF_TYPE_INT32

    ap_info_msg := List
    if msg_offset_ < ap_list_.size:
      ap_num := min (ap_list_.size - msg_offset_) report_count_
      ap_num.repeat:
        ap_node := ap_list_[msg_offset_ + it]
        ap_info := {
          RESP_RESULT_ENTRIES_SSID_: ap_node[wifi.SCAN_AP_SSID],
          RESP_RESULT_ENTRIES_CHANNEL_: ap_node[wifi.SCAN_AP_CHANNEL],
          RESP_RESULT_ENTRIES_RSSI_: ap_node[wifi.SCAN_AP_RSSI],
          RESP_RESULT_ENTRIES_BSSID_: ap_node[wifi.SCAN_AP_BSSID],
          RESP_RESULT_ENTRIES_AUTH_: ap_node[wifi.SCAN_AP_AUTHMODE],
        }
        ap_info_msg.add ap_info

      msg_offset_ += ap_num

    resp_msg := {
      MSG_: MSG_RESP_RESULT_,
      RESP_RESULT_: {
        RESP_RESULT_ENTRIES_: ap_info_msg
      }
    }
    resp := protobuf_map_to_bytes --message=resp_msg
    return resp

  run data/ByteArray -> ByteArray:
    resp := #[]
    
    r := protobuf.Reader data
    r.read_message:
      r.read_field MSG_:
        msg_id := r.read_primitive protobuf.PROTOBUF_TYPE_INT32
      r.read_field REQ_START_:
        resp = scan_start_ r
      r.read_field REQ_STATUS_:
        /* return to skip invalid message from host */
        resp = scan_status_
        return resp
      r.read_field REQ_RESULT_:
        resp = scan_result_ r

    return resp

class ConfigProcess extends Process:
  static MSG_ ::= 1
  static MSG_REQ_STATUS_  ::= 0
  static MSG_RESP_STATUS_ ::= 1
  static MSG_SET_CONFIG_  ::= 2
  static MSG_RESP_CONFIG_ ::= 3
  static MSG_SET_APPLY_   ::= 4
  static MSG_RESP_APPY_   ::= 5

  static REQ_STATUS_ ::= 10

  static RESP_STATUS_ ::= 11
  static RESP_STATUS_CONNECTED_ ::= 11
  static RESP_STATUS_CONNECTED_IPV4_ADDR_ ::= 1
  static RESP_STATUS_CONNECTED_AUTH_MODE_ ::= 2
  static RESP_STATUS_CONNECTED_SSID_      ::= 3
  static RESP_STATUS_CONNECTED_BSSID_     ::= 4
  static RESP_STATUS_CONNECTED_CHANNEL_   ::= 5

  static SET_CONFIG_ ::= 12
  static SET_CONFIG_SSID_     ::= 1
  static SET_CONFIG_PASSWORD_ ::= 2

  ssid_/string := ""
  password_/string := ""
  network_ := null

  set_config_ r/protobuf.Reader -> ByteArray:
    r.read_message:
      r.read_field SET_CONFIG_SSID_:
        ssid_ = r.read_primitive protobuf.PROTOBUF_TYPE_STRING
      r.read_field SET_CONFIG_PASSWORD_:
        password_ = r.read_primitive protobuf.PROTOBUF_TYPE_STRING
    
    resp_msg := {
      MSG_: MSG_RESP_CONFIG_
    }
    resp := protobuf_map_to_bytes --message=resp_msg
    return resp

  set_apply_ -> ByteArray:
    network_ = wifi.open
        --ssid=ssid_
        --password=password_

    resp_msg := {
        MSG_: MSG_RESP_APPY_
    }
    resp := protobuf_map_to_bytes --message=resp_msg
    return resp   

  req_status_ -> ByteArray:
    ipv4_addr := "$(network_.address)"
    auth_mode := 3
    bssid := #[0x8c, 0xab, 0x8e, 0xbb, 0x82, 0x08]
    channel := 6

    resp_msg := {
      MSG_: MSG_RESP_STATUS_,
      RESP_STATUS_: {
        RESP_STATUS_CONNECTED_: {
          RESP_STATUS_CONNECTED_IPV4_ADDR_: ipv4_addr,
          RESP_STATUS_CONNECTED_AUTH_MODE_: auth_mode,
          RESP_STATUS_CONNECTED_SSID_: ssid_,
          RESP_STATUS_CONNECTED_BSSID_: bssid,
          RESP_STATUS_CONNECTED_CHANNEL_: channel,
        }
      }
    }
    resp := protobuf_map_to_bytes --message=resp_msg
    return resp     

  run data/ByteArray -> ByteArray:
    msg_id := null
    resp := #[]

    r := protobuf.Reader data
    r.read_message:
      r.read_field MSG_:
        msg_id = r.read_primitive protobuf.PROTOBUF_TYPE_INT32
        if msg_id == MSG_SET_APPLY_:
          resp = set_apply_
      r.read_field SET_CONFIG_:
        resp = set_config_ r
      r.read_field REQ_STATUS_:
        resp = req_status_

    return resp

class Provisioning:
  service_/BLEService := ?
  security_/Security := ?
  wifi_config_/WiFiConfig := WiFiConfig

  static VERSION_ID_ := "v1.1"
  static BASE_CAPS_ := ["wifi_scan"]
  static DEBUG_ := true

  constructor.ble service_uuid/ByteArray service_name/string .security_/Security:
    service_ = BLEService service_uuid service_name
  
  constructor.ble_with_uuid service_name/string security/Security:
    return Provisioning.ble SERVICE_UUID service_name security

  start -> none:
    ch_ver_process_

    task:: ch_config_task_
    task:: ch_session_task_
    task:: ch_scan_task_

  ch_ver_process_:
    caps := BASE_CAPS_
    sec_ver := security_.version
    if sec_ver == 0:
      caps.add "no_sec"
    ver_map := {"prov":{"ver":VERSION_ID_, "sec_ver":sec_ver, "cap":caps}}
    ver_json := json.stringify ver_map

    characteristic := service_["proto-ver"]
    characteristic.write ver_json.to_byte_array

  static common_process_ security/Security process/Process characteristic/BLECharacteristic:
    encrypt_data := characteristic.read
    data := security.decrypt encrypt_data
    if DEBUG_:
      print "read from $(characteristic.desc_): $(data)"
    resp := process.run data
    if resp.size > 0:
      if DEBUG_:
        print "write to $(characteristic.desc_): $(resp)"
      data = security.encrypt resp
      characteristic.write data

  ch_scan_task_:
    characteristic := service_["prov-scan"]
    session_process := ScanProcess
    while true:
      common_process_ security_ session_process characteristic

  ch_session_task_:
    characteristic := service_["prov-session"]
    session_process := SessionProcess
    while true:
      common_process_ security_ session_process characteristic

  ch_config_task_:
    characteristic := service_["prov-config"]
    session_process := ConfigProcess
    while true:
      common_process_ security_ session_process characteristic  

protobuf_map_to_bytes --message/Map /* field:value */ -> ByteArray:
  buffer := bytes.Buffer
  w := protobuf.Writer buffer

  message.do:
    if it is not int:
      throw "WRONG_OBJECT_TYPE"
    value := message[it]
    if value is int:
      w.write_primitive protobuf.PROTOBUF_TYPE_INT32 value --as_field=it
    else if value is string:
      w.write_primitive protobuf.PROTOBUF_TYPE_STRING value --as_field=it
    else if value is ByteArray:
      w.write_primitive protobuf.PROTOBUF_TYPE_BYTES value --as_field=it
    else if value is List:
      id := it
      value.do:
        w.write_primitive
            protobuf.PROTOBUF_TYPE_BYTES
            protobuf_map_to_bytes --message=it
            --as_field=id
    else if value is Map:
      w.write_primitive 
          protobuf.PROTOBUF_TYPE_BYTES
          protobuf_map_to_bytes --message=value
          --as_field=it
    else:
      throw "WRONG_OBJECT_TYPE"

  return buffer.bytes

get_mac_address -> ByteArray:
  #primitive.esp32.get_mac_address
