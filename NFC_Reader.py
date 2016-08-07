from smartcard.scard import *
from smartcard.util import toHexString
import smartcard.util
from smartcard.ATR import ATR
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
import time
import struct

'''
Definitions:
ISO/IEC 14443 Identification cards -- Contactless integrated circuit cards -- Proximity cards is an international standard that defines proximity cards used for identification, and the transmission protocols for communicating with it.
(ATR) Answer To Reset: is a message output by a contact Smart Card conforming to ISO/IEC 7816 standards, following electrical reset of the card's chip by a card reader.
PCD: proximity coupling device (the card reader)
PICC: proximity integrated circuit card



'''

attributes = {
	SCARD_ATTR_ATR_STRING: 'SCARD_ATTR_ATR_STRING',
	SCARD_ATTR_CHANNEL_ID: 'SCARD_ATTR_CHANNEL_ID',
	SCARD_ATTR_CHARACTERISTICS: 'SCARD_ATTR_CHARACTERISTICS',
	SCARD_ATTR_CURRENT_BWT: 'SCARD_ATTR_CURRENT_BWT',
	SCARD_ATTR_CURRENT_CWT: 'SCARD_ATTR_CURRENT_CWT',
	SCARD_ATTR_CURRENT_EBC_ENCODING: 'SCARD_ATTR_CURRENT_EBC_ENCODING',
	SCARD_ATTR_CURRENT_F: 'SCARD_ATTR_CURRENT_F',
	SCARD_ATTR_CURRENT_IFSC: 'SCARD_ATTR_CURRENT_IFSC',
	SCARD_ATTR_CURRENT_IFSD: 'SCARD_ATTR_CURRENT_IFSD',
	SCARD_ATTR_CURRENT_IO_STATE: 'SCARD_ATTR_CURRENT_IO_STATE',
	SCARD_ATTR_DEFAULT_DATA_RATE: 'SCARD_ATTR_DEFAULT_DATA_RATE',
	SCARD_ATTR_DEVICE_FRIENDLY_NAME_A: 'SCARD_ATTR_DEVICE_FRIENDLY_NAME_A',
	SCARD_ATTR_DEVICE_FRIENDLY_NAME_W: 'SCARD_ATTR_DEVICE_FRIENDLY_NAME_W',
	SCARD_ATTR_DEVICE_SYSTEM_NAME_A: 'SCARD_ATTR_DEVICE_SYSTEM_NAME_A',
	SCARD_ATTR_DEVICE_SYSTEM_NAME_W: 'SCARD_ATTR_DEVICE_SYSTEM_NAME_W',
	SCARD_ATTR_DEVICE_UNIT: 'SCARD_ATTR_DEVICE_UNIT',
	SCARD_ATTR_ESC_AUTHREQUEST: 'SCARD_ATTR_ESC_AUTHREQUEST',
	SCARD_ATTR_EXTENDED_BWT: 'SCARD_ATTR_EXTENDED_BWT',
	SCARD_ATTR_ICC_INTERFACE_STATUS: 'SCARD_ATTR_ICC_INTERFACE_STATUS',
	SCARD_ATTR_ICC_PRESENCE: 'SCARD_ATTR_ICC_PRESENCE',
	SCARD_ATTR_ICC_TYPE_PER_ATR: 'SCARD_ATTR_ICC_TYPE_PER_ATR',
	SCARD_ATTR_MAXINPUT: 'SCARD_ATTR_MAXINPUT',
	SCARD_ATTR_MAX_CLK: 'SCARD_ATTR_MAX_CLK',
	SCARD_ATTR_MAX_DATA_RATE: 'SCARD_ATTR_MAX_DATA_RATE',
	SCARD_ATTR_POWER_MGMT_SUPPORT: 'SCARD_ATTR_POWER_MGMT_SUPPORT',
	SCARD_ATTR_SUPRESS_T1_IFS_REQUEST: 'SCARD_ATTR_SUPRESS_T1_IFS_REQUEST',
	SCARD_ATTR_USER_AUTH_INPUT_DEVICE: 'SCARD_ATTR_USER_AUTH_INPUT_DEVICE',
	SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE:
		'SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE',
	SCARD_ATTR_VENDOR_IFD_SERIAL_NO: 'SCARD_ATTR_VENDOR_IFD_SERIAL_NO',
	SCARD_ATTR_VENDOR_IFD_TYPE: 'SCARD_ATTR_VENDOR_IFD_TYPE',
	SCARD_ATTR_VENDOR_IFD_VERSION: 'SCARD_ATTR_VENDOR_IFD_VERSION',
	SCARD_ATTR_VENDOR_NAME: 'SCARD_ATTR_VENDOR_NAME',
}

BLOCK_NUMBER = 0x04
AUTHENTICATE = [0xFF, 0x88, 0x00, BLOCK_NUMBER, 0x60, 0x00]

COMMAND = [0xFF, 0xCA, 0x00, 0x00, 0x00]


SELECT = [0xA0, 0xA4, 0x00, 0x00, 0x02]

GET_UID = [0xFF,0xCA,0x00,0x00,0x04]
#GET_ATS = [0xFF,0xCA,0x00,0x01,0x04]

READ_BYTES = [0xFF,0xB0,0x00,0x04,0x04]
WRITE_BLOCKS = [0xFF,0xD6,0x00,0x04,0x04,0xFF,0xFF,0xFF,0xFF] # Data are the last three items in the list.


READ_16_BINARY_BLOCKS = [0xFF,0xB0,0x00,0x04,0x10] # Read 16 bytes from the binary block 0x04h.
READ_4_BINARY_BLOCKS = [0xFF,0xB0,0x00,0x04,0x04] # Read 16 bytes from the binary block 0x04h.
READ_16_BINARY_BLOCKS_FROM_04 = [0xFF,0xB0,0x00,0x04,0x10] # Read 16 bytes from the binary block 0x04h.

READ_ATS = [0xFF,0xCA,0x01,0x00,0x04]

GET_UID_APDU = [0xFF,0xCA,0x00,0x00,0x00]

#SET_PICC_OPERATING_PARAMETER = [0xFF,0x00,0x51,0x01,0x00]
GET_PICC_SERIAL = [0xFF,0xCA,0x00,0x00,0x04]
GET_ATS_APDU = [0xFF,0xCA,0x00,0x00,0x01]
GET_GET_CHALLENGE = [0x00, 0x84,0x00,0x00,0x08]


class NFC_Reader():
	def __init__(self, uid = ""):
		self.uid = uid
		self.hresult, self.hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
		self.hresult, self.readers = SCardListReaders(self.hcontext, [])
		self.reader = self.readers[0]
		self.hresult, self.hcard, self.dwActiveProtocol = SCardConnect(
				self.hcontext,
				self.reader,
				SCARD_SHARE_SHARED,
				SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)

	def get_card_status(self):
		hresult, reader, state, protocol, atr = SCardStatus(self.hcard)
		print("Getting card status...")
		if hresult != SCARD_S_SUCCESS:
			raise error, 'failed to get status: ' + SCardGetErrorMessage(hresult)
		
		print 'Reader: ', reader
		print 'State: ', state
		print 'Protocol: ', protocol
		print 'ATR: ',
		for i in xrange(len(atr)):
			print '0x%.2X' % i,
		print("\n")
		converted = toHexString(atr, format=0)
		print("Initial Header, T0 , TD1, TD1, T1, Tk, TCK")
		print(converted)
		print("3B 86 80 01 06 75 77 81 02 80 00h")
		print("------------------------\n")


	def read_uid(self):
		print("Reading the UID...")
		for iteration in range(1):
			hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
			assert hresult==SCARD_S_SUCCESS
			hresult, readers = SCardListReaders(hcontext, [])
			assert len(readers) > 0
			reader = readers[0]
			print("Found reader: " +  str(reader))
			hresult, hcard, dwActiveProtocol = SCardConnect(
				hcontext,
				reader,
				SCARD_SHARE_SHARED,
				SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
			try:
				hresult, response = SCardTransmit(hcard,dwActiveProtocol,COMMAND)
				uid = toHexString(response, format=0)
				print("UID: " + uid +  " , Response:  " + str(response) + " HResult: " + str(hresult))
			except SystemError:
				print ("No Card Found")
			time.sleep(1)
		print("------------------------\n")


	def read_values(self):
		print("Reading values from card...")
		for iteration in range(1):
			hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
			assert hresult==SCARD_S_SUCCESS
			hresult, readers = SCardListReaders(hcontext, [])
			assert len(readers) > 0
			reader = readers[0]
			print("Found reader: " +  str(reader))
			hresult, hcard, dwActiveProtocol = SCardConnect(
				hcontext,
				reader,
				SCARD_SHARE_SHARED,
				SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
			try:
				hresult, response = SCardTransmit(self.hcard,dwActiveProtocol,GET_ATS_APDU)
				uid = toHexString(response, format=0)
				print("UID: " + uid +  " , Response:  " + str(response) + " HResult: " + str(hresult))
			except SystemError:
				print ("No Card Found")
			time.sleep(1)
		print("------------------------\n")


	def send_command(self, command):
		print("Sending command...")
		for iteration in range(1):
			hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
			assert hresult==SCARD_S_SUCCESS
			hresult, readers = SCardListReaders(hcontext, [])
			assert len(readers) > 0
			reader = readers[0]
			print("Found reader: " +  str(reader))
			hresult, hcard, dwActiveProtocol = SCardConnect(
				hcontext,
				reader,
				SCARD_SHARE_SHARED,
				SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
			try:
				hresult, response = SCardTransmit(self.hcard,dwActiveProtocol,command)
				value = toHexString(response, format=0)
				print("Value: " + value +  " , Response:  " + str(response) + " HResult: " + str(hresult))
			except SystemError:
				print ("No Card Found")
			time.sleep(1)
		print("------------------------\n")

	def printAttribute(self, attrib, value):
		print('-----------------', attributes[attrib], '-----------------')
		print(value)
		print(toHexString(value, smartcard.util.HEX))
		print(struct.pack(*['<' + 'B' * len(value)] + value))

	def get_attributes(self):
		try:
			for i in list(attributes.keys()):
				hresult, attrib = SCardGetAttrib(self.hcard, i)
				if (hresult == SCARD_S_SUCCESS):
					self.printAttribute(i, attrib)
				else:
					print('-----------------', attributes[i], '-----------------')
					print('unsupported')
		finally:
			hresult = SCardDisconnect(self.hcard, SCARD_UNPOWER_CARD)
			if hresult != SCARD_S_SUCCESS:
				raise error(
					'Failed to disconnect: ' + \
					SCardGetErrorMessage(hresult))
			print('Disconnected')



if __name__ == '__main__':
	reader = NFC_Reader()
	reader.get_card_status()
	reader.read_uid()
	reader.read_values()
	reader.send_command(AUTHENTICATE)
	reader.send_command(READ_16_BINARY_BLOCKS)
	#reader.get_attributes()




