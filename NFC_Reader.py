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


Definitions:
ISO/IEC 14443 Identification cards -- Contactless integrated circuit cards -- Proximity cards is an international standard that defines proximity cards used for identification, and the transmission protocols for communicating with it.
(ATR) Answer To Reset: is a message output by a contact Smart Card conforming to ISO/IEC 7816 standards, following electrical reset of the card's chip by a card reader.
PCD: proximity coupling device (the card reader)
PICC: proximity integrated circuit card



RFID Reader/Writer:
///////ACR122U///////////////
RFID/NFC Reader/Writer: ACR122U-A9
Supported Frequency: 13.56MHz
Supported ISO: 14443-4A/B, ISO 18092.
	\-> ISO 14443 Type A and B cards, MIFARE, FeliCa, and all 4 types of NFC (ISO/IEC 18092) tags
Additional Supported Standards: Mifare, FeliCa, four types of NFC.
Documentation: http://downloads.acs.com.hk/drivers/en/API-ACR122U-2.02.pdf


RFID Tags:

////////Card RFID////////////
Protocol: ISO14443A
Working frequency: 13.56 MHZ
Reading and writing distance: 0 to 10cm
Packaging materials: Pack PVC NFC Smart Card Tag 
3.56MHz ISO14443A S50 card reader
Frequency: 13.56 MHz
Material: PVC
Size: Approx. 8.5 x 5.4 x 0.1cm/ 3 x 2 x 0.04"
Protocol: ISO14443A

////////Paper Tag RFID///////
Protocol: ISO14443A
Working frequency: 13.56 MHZ
Reading and writing distance: 1 to 5 cm
Chip: Ntag213
Physical capacity: 180 bytes
Usable capacity: 144 bytes
Reading and writing time: 1 to 2 ms
Working temperature: -20 to 55 degree, humidity of 90%
Erase times : > 100000 times
Data storage: > 10 years
Reading time: 100000 times
Diameter: 27mm
Packaging materials: PE self-adhesive +  coated paper



'''
VERBOSE = True

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
AUTHENTICATE_CARD = [0xFF, 0x88, 0x00, BLOCK_NUMBER, 0x60, 0x00]

PPR_TAG_BLOCK_NUMBER = 0x01
AUTHENTICATE_PAPER_TAG = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x05, 0x60, 0x00]

COMMAND = [0xFF, 0xCA, 0x00, 0x00, 0x00]

SELECT = [0xA0, 0xA4, 0x00, 0x00, 0x02]

GET_UID = [0xFF,0xCA,0x00,0x00,0x04]

READ_BYTES = [0xFF,0xB0,0x00,0x04,0x04]
WRITE_BLOCKS = [0xFF,0xD6,0x00,0x04,0x04,0xFF,0xFF,0xFF,0xFF] # Data are the last three items in the list.


READ_16_BINARY_BLOCKS = [0xFF,0xB0,0x00,0x04,0x10] # Read 16 bytes from the binary block 0x04h.
READ_4_BINARY_BLOCKS = [0xFF,0xB0,0x00,0x04,0x04] # Read 4 bytes from the binary block 0x04h.


NUMBER_BYTES_TO_UPDATE = 0x10
UPDATE_TEN_BLOCKS = [0xFF, 0xD6, 0x00, BLOCK_NUMBER, NUMBER_BYTES_TO_UPDATE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]


UPDATE_FIXED_BLOCKS = [0xFF, 0xD6, 0x00, BLOCK_NUMBER, NUMBER_BYTES_TO_UPDATE]


UPDATE_BLOCKS_WITH_DATA = [0xFF, 0xD6, 0x00, BLOCK_NUMBER]
READ_BLOCKS_RECENTLY_UPDATED = [0xFF,0xB0,0x00,BLOCK_NUMBER]

CARD_TAG = [0x01]
PAPER_TAG = [0x02]


class NFC_Reader():
	def __init__(self):
		self.hresult, self.hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
		self.hresult, self.readers = SCardListReaders(self.hcontext, [])
		assert len(self.readers) > 0
		self.reader = self.readers[0]
		print("-------------------------------------------------------")
		print("Checking for card reader...")
		print("Found reader: " +  str(self.reader))
		print("Initializing card reader...")
		self.hresult, self.hcard, self.dwActiveProtocol = SCardConnect(
				self.hcontext,
				self.reader,
				SCARD_SHARE_SHARED,
				SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
		self.data_blocks = []

	def get_tag_status(self):
		hresult, reader, state, protocol, atr = SCardStatus(self.hcard)
		print("-------------------------------------------------------")

		print("Getting card status...")
		if hresult != SCARD_S_SUCCESS:
			raise error, 'failed to get status: ' + SCardGetErrorMessage(hresult)

		print("---------------------------")
		print 'Reader: ', reader
		print 'State: ', state
		print 'Protocol: ', protocol
		print 'ATR: ',
		for i in xrange(len(atr)):
			print '0x%.2X' % i,
		print("\n")
		converted = toHexString(atr, format=0)
		return converted


	def read_uid(self):
		value, self.uid = self.send_command(GET_UID)
		print("------------------------")
		print("UID: " + toHexString(value, format=0))
		print("------------------------")


	def send_command(self, command):
		#print("Sending command...")
		for iteration in range(1):
			try:
				self.hresult, self.response = SCardTransmit(self.hcard,self.dwActiveProtocol,command)
				value = toHexString(self.response, format=0)
				if(VERBOSE):
					print("Sent command " + self.hex_to_string(command))
					print("Value: " + value +  " , Response:  " + str(self.response) + " HResult: " + str(self.hresult))
			except SystemError:
				print ("No Card Found")
			time.sleep(1)
		return self.response, value

	def write_card_tag_data(self, string):
		print("-------------------------------------------------------")
		int_array = map(ord, string)
		print("Writing data: " + str(int_array))

		# If the string is greater than 16 characters, break. 
		if(len(int_array) > 16):
			return

		# Add the converted string to hex blocks to the APDU command.
		for value in int_array:
			UPDATE_FIXED_BLOCKS.append(value)

		# Authenticate with the specified block with the APDU authenticate command.
		response, value = self.send_command(AUTHENTICATE_CARD)

		print("Writing " + string + " to card...")
		if(response == [144, 0]):
			print("Authentication successful.")

			if(len(string) > 0):
				print("Writing data blocks...")
				self.send_command(UPDATE_FIXED_BLOCKS)
			else:
				print("Please provide a valid string.")
		else:
			print("Unable to authenticate when writing.")	
		print("------------------------\n")
		

	def write_paper_tag_data(self,string):
		print("-------------------------------------------------------")
		int_array = map(ord, string)
		print("Writing data: " + str(int_array))

		# If the string is greater than 16 characters, break. 
		if(len(int_array) > 16):
			return

		# Add the converted string to hex blocks to the APDU command.
		for value in int_array:
			UPDATE_FIXED_BLOCKS.append(value)

		print("Writing " + string + " to card...")

		if(len(string) > 0):
			print("Writing data blocks...")
			self.send_command(UPDATE_FIXED_BLOCKS)
		else:
			print("Please provide a valid string.")
		
		print("------------------------\n")

	def read_card_tag_data(self):
		print("-------------------------------------------------------")
		print("Reading card tag data...")
		response, value = self.send_command(AUTHENTICATE_CARD)

		if(response == [144, 0]):
			print("Authentication successful.")
			print("Reading data blocks...")
			result, value = self.send_command(READ_16_BINARY_BLOCKS)

			if(VERBOSE):
				print("Value: " + value +  " , Response:  " + str(result))
			print("-------------------------------------------------------")
			return result
		else:
			print("Unable to authenticate when reading.")



	def read_paper_tag_data(self):
		print("-------------------------------------------------------")
		print("Reading a paper tag's data...")
		# No authentication is required with this kind of tag.

		result, value = self.send_command(READ_16_BINARY_BLOCKS)

		if(VERBOSE):
			print("Value: " + value +  " , Response:  " + str(result))
		print("-------------------------------------------------------")
		return result
		


	def hex_to_string(self, hex):
		return toHexString(hex, format=0)



def card_tag_testing():
	reader = NFC_Reader()

	# 2. Obtain the card status
	reader.get_tag_status()

	# 3. Read the UID
	reader.read_uid()

	# 4. Read the data from the card.
	value = reader.read_card_tag_data()
	print("Read " + str(value) + " from the card.")

	# 5. Write a string to the byte blocks.
	reader.write_card_tag_data("Another")

	# 6. Read the data blocks to verify they were written correctly.
	value = reader.read_card_tag_data()
	print("Read " + str(value) + " from the card.")


def paper_tag_testing():
	# 1. Create an NFC_Reader
	reader = NFC_Reader()

	# 2. Obtain the card status
	reader.get_tag_status()

	# 3. Read the UID
	reader.read_uid()

	# 4. Read the data from the card.
	value = reader.write_paper_tag_data()
	print("Read " + str(value) + " from the card.")

	# 5. Write a string to the byte blocks.
	reader.write_paper_tag_data("Testing")

	# 6. Read the data blocks to verify they were written correctly.
	value = reader.read_paper_tag_data()
	print("Read " + str(value) + " from the card.")


if __name__ == '__main__':
	# 1. Create an NFC_Reader
	reader = NFC_Reader()

	# 2. Obtain the card status
	reader.get_tag_status()

	# 3. Read the UID
	reader.read_uid()

	# 4. Read the data from the card.
	value = reader.read_paper_tag_data()
	print("Read " + str(value) + " from the card.")

	
	# 5. Write a string to the byte blocks.
	reader.write_paper_tag_data("Testing")

	# 6. Read the data blocks to verify they were written correctly.
	value = reader.read_paper_tag_data()
	print("Read " + str(value) + " from the card.")



