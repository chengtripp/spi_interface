# SPDX-FileCopyrightText: 2018 Brent Rubell for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""
Example for using the RFM9x Radio with Raspberry Pi.

Learn Guide: https://learn.adafruit.com/lora-and-lorawan-for-raspberry-pi
Author: Brent Rubell for Adafruit Industries

Packet Parsing inspired by https://github.com/faragher/Reticulum-Packet-Decoder

"""
# Import Python System Libraries
import time
# Import Blinka Libraries
import busio
from digitalio import DigitalInOut, Direction, Pull
import board
# Import RFM9x
import adafruit_rfm9x

# Header, 2 bytes:
# 1: 
hIFAC            = 0b10000000# 1 bit
hHeaderType      = 0b01000000# 1 bit
hContext         = 0b00100000# 1 bit
hPropagationType = 0b00010000# 1 bit
hDestinationType = 0b00001100# 2 bits
hPacketType      = 0b00000011# 2 bits
# 2: Hops

ContextEnum = {

  0x00: "None"


}

IFACEnum = {
  0x00: "Disabled      (0)",
  0x01: "Authenticated (1)"
}

HeaderEnum = {
  0x00: "Type 1        (0)",
  0x01: "Type 2        (1)"
}

PropagationEnum = {
  0x00: "Broadcast    (00)",
  0x01: "Transport    (01)",
  0x02: "Reserved     (10)",
  0x03: "Reserved     (11)"
}

DestinationEnum = {
  0x00: "Single       (00)",
  0x01: "Group        (01)",
  0x02: "Plain        (10)",
  0x03: "Link         (11)"
}

HeaderContextEnum = {
  0x00: "Unknown       (0)",
  0x01: "Unknown       (1)"

}

AnnounceHeaderContextEnum = {
  0x00: "No Ratchet    (0)",
  0x01: "Ratchet       (1)"

}

PacketTypeEnum = {
  0x00: "Data         (00)",
  0x01: "Announce     (01)",
  0x02: "Link Request (10)",
  0x03: "Proof        (11)"
}

ContextEnum = {
  0x00: "None",
  0x01: "Resource",
  0x02: "Resource Advertisement",
  0x03: "Resource Part Request",
  0x04: "Resource Hashmap Update",
  0x05: "Resource Proof",
  0x06: "Resource Initiator Cancel",
  0x07: "Resource Receiver Cancel",
  0x08: "Cache Request",
  0x09: "Request",
  0x0a: "Response",
  0x0b: "Path Response",
  0x0c: "Command",
  0x0d: "Command Status",
  0x0e: "Channel",
  0xfa: "Keepalive",
  0xfb: "Link Peer Identification Proof",
  0xfc: "Link Close",
  0xfd: "Link Proof",
  0xfe: "Link Request Time Measurement",
  0xff: "Link Request Proof"
  
}

Codes = {
  "Announce": 0x01,
  "Ratchet": 0x01
}

def GetContext(con):
  if con in ContextEnum:
    return ContextEnum[con]
  else:
    return "Undefined - "+str(hex(con))

def RawData(Data):
  print("### Raw Data ###")
  print("Length: "+str(len(Data)))
  print("Bytes: ")
  print(Data.hex())
  print(" ")
  print("UTF-8: ")# Ignores errors
  print(Data.decode("utf-8",errors="replace"))

def ParsePacket(data):
  print("")
  print("##################")
  print("### NEW PACKET ###")
  print("##################")
  print("")
  print("Shift Along")
  data = data[1:]

  new_header = data[:19]
  print(" ".join(hex(n) for n in new_header))

  print("")
  print(" ".join(hex(n) for n in data))

  # Header
  IFAC = (hIFAC&data[0])>>7
  HeaderType = (hHeaderType&data[0])>>6
  HeaderContext = (hContext&data[0])>>5
  PropagationType = (hPropagationType&data[0])>>4
  DestinationType = (hDestinationType&data[0])>>2
  PacketType = hPacketType&data[0]

  Hops = data[1]


  # print(bin(data[0]).replace("0b",""))
  print("### Header ###")
  print("IFAC:             "+IFACEnum[IFAC])
  print("Header Type:      "+HeaderEnum[HeaderType])
  if PacketType == 1:
    print("Header Context:   "+AnnounceHeaderContextEnum[HeaderContext])
  else:
    print("Header Context:   "+HeaderContextEnum[HeaderContext])
  print("Propagation Type: "+PropagationEnum[PropagationType])
  print("Destination Type: "+DestinationEnum[DestinationType])
  print("Packet Type:      "+PacketTypeEnum[PacketType])

  # print(data[1])
  print("Hops:             "+str(Hops))

  HashOne = data[2:18]
  if(HeaderType == 1):
    HashTwo = data[18:34]

  print("")
  print("### Hash(es) ###")
  print("Hash1: "+str(HashOne.hex()))
  if(HeaderType == 1):
    print("Hash2: "+str(HashTwo.hex()))
  else:
    print("Hash2: N/A")

  print("")
  print("### Context ###")
  if(HeaderType==1):
    Context = data[34]
  else:
    Context = data[18]
  print("Context: "+GetContext(Context))
  print("")
  if(HeaderType==1):
    data = data[35:]
  else:
    data = data[19:]

  if PacketType == 1:
    AnnounceData(data,HeaderContext)
  elif DestinationType == 3:
    print("### Link data is encrypted ###")
    print("")
  else:
    RawData(data)

def AnnounceData(Data,HeaderContext):
  print("### Announce Data ###")
  PubKey = Data[:64]
  NameHash = Data[64:74]
  RandomHash = Data[74:84]
  Signature = Data[84:148]
  if HeaderContext == Codes["Ratchet"]:
    Ratchet = Data[148:180]
    AppData = Data[180:]
  else:
    AppData = Data[148:]
  
  print("Public Key:  "+str(PubKey.hex()))
  print("Name Hash:   "+str(NameHash.hex()))
  print("Random Hash: "+str(RandomHash.hex()))
  print("Signature:   "+str(Signature.hex()))
  if HeaderContext == Codes["Ratchet"]:
    print("Ratchet:     "+str(Ratchet.hex()))
  print("Raw AppData: "+str(AppData.hex()))
  print("      UTF-8: "+str(AppData.decode("utf-8",errors="ignore")))
  print("")
  if AppData != None and AppData != b"":
    if AppData[0] == 0x93:
      print("Propagation node:")
      if AppData[1] == 0xc3:
        print("    Active")
      elif AppData[1] == 0xc2:
        print("    Inactive")
      buffer = AppData[3:7]
      print("    Time:     "+str(int.from_bytes(buffer,"big")))
      buffer = 0
      if AppData[7]== 0xcd:
        buffer = int.from_bytes(AppData[8:10],"big")
      elif AppData[7] == 0xcb:
        buffer = AppData[8:16]
        print("    WARNING: Using float64, not uint16!")
        print("    Find this system and fix it!")
        import struct
        buffer = struct.unpack(">d",buffer)[0]
      if buffer != 0:
        print("    Max Size: "+str(buffer)+" KB")
    elif AppData[0] == 0x92:
      if AppData[1] == 0xc4:
        buffer = bytearray(b"")
        for i in range(3,AppData[2]+3):
          buffer.append(AppData[i])
        print("Announced Name: "+str(buffer.decode('utf-8')))
        if AppData[3+AppData[2]] != 0xc0:
          print("Ticket:         "+str(AppData[3+AppData[2]]))
        else:
          print("Ticket:          None")

# Configure LoRa Radio
CS = DigitalInOut(board.CE1)
RESET = DigitalInOut(board.D25)
spi = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)
rfm9x = adafruit_rfm9x.RFM9x(spi, CS, RESET, 867.2)
rfm9x.tx_power = 7
rfm9x.signal_bandwidth = 125000
rfm9x.coding_rate = 5
rfm9x.spreading_factor = 8
rfm9x.enable_crc = False
rfm9x.preamble_length = 18
prev_packet = None

while True:
    packet = None

    # check for packet rx
    packet = rfm9x.receive_raw()
    if packet is None:
        print('- Waiting for PKT -')
    else:
        if len(packet) > 10:
            prev_packet = packet
 #          RawData(packet)

            ParsePacket(packet)

            time.sleep(1)

    time.sleep(0.1)
