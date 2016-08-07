from smartcard.scard import *
from smartcard.util import toHexString
import smartcard.util
from smartcard.ATR import ATR
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
import time
import struct
import array

'''
RFID/NFC Reader/Writer: ACR122U-A9
Supported Frequency: 13.56MHz
Supported ISO: 14443-4A/B, ISO 18092.
Additional Supported Standards: Mifare, FeliCa, four types of NFC.
Documentation: http://downloads.acs.com.hk/drivers/en/API-ACR122U-2.02.pdf


Definitions:
ISO/IEC 14443 Identification cards -- Contactless integrated circuit cards -- Proximity cards is an international standard that defines proximity cards used for identification, and the transmission protocols for communicating with it.
(ATR) Answer To Reset: is a message output by a contact Smart Card conforming to ISO/IEC 7816 standards, following electrical reset of the card's chip by a card reader.
PCD: proximity coupling device (the card reader)
PICC: proximity integrated circuit card


'''
VERBOSE = False

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

READ_BYTES = [0xFF,0xB0,0x00,0x04,0x04]
WRITE_BLOCKS = [0xFF,0xD6,0x00,0x04,0x04,0xFF,0xFF,0xFF,0xFF] # Data are the last three items in the list.


READ_16_BINARY_BLOCKS = [0xFF,0xB0,0x00,0x04,0x10] # Read 16 bytes from the binary block 0x04h.
READ_4_BINARY_BLOCKS = [0xFF,0xB0,0x00,0x04,0x04] # Read 4 bytes from the binary block 0x04h.


NUMBER_BYTES_TO_UPDATE = 0x10
UPDATE_BLOCKS = [0xFF, 0xD6, 0x00, BLOCK_NUMBER, NUMBER_BYTES_TO_UPDATE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]


UPDATE_FIXED_BLOCKS = [0xFF, 0xD6, 0x00, BLOCK_NUMBER, NUMBER_BYTES_TO_UPDATE]


UPDATE_BLOCKS_WITH_DATA = [0xFF, 0xD6, 0x00, BLOCK_NUMBER]
READ_BLOCKS_RECENTLY_UPDATED = [0xFF,0xB0,0x00,BLOCK_NUMBER]


class NFC_Reader():
	def __init__(self, uid = ""):
		self.uid = uid
		self.hresult, self.hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
		self.hresult, self.readers = SCardListReaders(self.hcontext, [])
		assert len(self.readers) > 0
		self.reader = self.readers[0]
		print("Found reader: " +  str(self.reader))
		
		self.hresult, self.hcard, self.dwActiveProtocol = SCardConnect(
				self.hcontext,
				self.reader,
				SCARD_SHARE_SHARED,
				SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
		self.data_blocks = []

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
		print("------------------------\n")
		return converted


	def read_uid(self):
		value, self.uid = self.send_command(GET_UID)
		print(self.uid)

	def send_command(self, command):
		print("Sending command...")
		for iteration in range(1):
			try:
				self.hresult, self.response = SCardTransmit(self.hcard,self.dwActiveProtocol,command)
				value = toHexString(self.response, format=0)
				if(VERBOSE):
					print("Value: " + value +  " , Response:  " + str(self.response) + " HResult: " + str(self.hresult))
			except SystemError:
				print ("No Card Found")
			time.sleep(1)
		print("------------------------\n")
		return self.response, value


	def write_data(self, string):
		int_array = map(ord, string)
		print("Writing data: " + str(int_array))

		# Write the number of entries to be written.
		UPDATE_BLOCKS_WITH_DATA.append(number_of_bytes)

		# Add the converted string to hex blocks to the APDU command.
		for value in int_array:
			UPDATE_FIXED_BLOCKS.append(value)

		# Authenticate with the specified block with the APDU authenticate command.
		response, value = self.send_command(AUTHENTICATE)

		print("Writing " + string + " to card...")
		if(response == [144, 0]):
			print("Authentication successful.")

			if(len(string) > 0):
				print("Writing data blocks...")
				self.send_command(UPDATE_FIXED_BLOCKS)
			else:
				print("Please provide a valid string.")
		else:
			print("Unable to authenticate.")	
		print("------------------------\n")


	def read_data(self):
		response, value = self.send_command(AUTHENTICATE)
		print("Reading data from card...")
		if(response == [144, 0]):
			print("Authentication successful.")
			print("Reading data blocks...")
			result, value = self.send_command(READ_16_BINARY_BLOCKS)

			if(VERBOSE):
				print("Value: " + value +  " , Response:  " + str(result))
			print("------------------------\n")
			return result
		else:
			print("Unable to authenticate.")
		
	# Returns a byte array.
	def encode_string_to_hex(self, string):
		print("Encoding " + str(string) + " to a byte array.")
		byte_array = []
		for character in string:
			if(len(character) > 0):
				encoded = character.encode('hex')
				byte_array.append(encoded)

		return byte_array

	def encode_hex_to_int(self, hex_value):
		print("Encoding " + str(hex_value) + " to an int.")
		int_array = []
		for value in hex_value:
			result = int(ord(value))
			int_array.append(result)
		return int_array


	def decode_from_hex(self, byte_array):
		print("Decoding byte array " + str(byte_array) + " to a string.")
		string = ""

		for entry in byte_array:
			if(len(entry) > 0):
				decoded = entry[2:].decode('hex')
				string += decoded
		print("String value: " + str(string))
		return string

	def decode_from_int(self, byte_array):
		print("Decoding byte array " + str(byte_array) + " to a string.")
		string = ""
		for entry in byte_array:
			decoded = entry.decode('hex')
			string += decoded
		print("String value: " + str(string))
		return string

	def convert_to_byte_array(self, int_array):
		print("Converting array to byte array")
		print(int_array)

		converted = array.array('B', int_array).tostring()
		
		return converted


if __name__ == '__main__':
	# 1. Create an NFC_Reader
	reader = NFC_Reader()

	# 2. Obtain the card status
	reader.get_card_status()

	# 3. Read the UID
	reader.read_uid()

	# 4. Read the data from the card.
	value = reader.read_data()
	print("Read " + str(value) + " from the card.")

	#reader.decode_from_int(value)

	# 5. Encode a value into a hex array.
	#encoded_value = reader.encode_string_to_hex("Hello")
	#print(encoded_value)

	# 6. Decode a hex array into a string.
	#decoded_value = reader.decode_from_hex(encoded_value)
	#print(decoded_value)


	reader.write_data("Four")

	value = reader.read_data()
	print("Read " + str(value) + " from the card.")


	#print(reader.decode_from_hex(encoded_value))

	

	#reader.send_command(UPDATE_BLOCKS)
	#reader.send_command(READ_16_BINARY_BLOCKS)

	#reader.get_attributes()




