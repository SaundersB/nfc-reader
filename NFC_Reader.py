from smartcard.scard import *
from smartcard.util import toHexString
from smartcard.ATR import ATR
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
import time


COMMAND = [0xFF, 0xCA, 0x00, 0x00, 0x00]
SELECT = [0x00, 0xA4, 0x04, 0x00, 0x0A, 0xA0, 0x00, 0x00, 0x00, 0x62,
    0x03, 0x01, 0x0C, 0x06, 0x01]
COMMAND2 = [0x00, 0x00, 0x00, 0x00]


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



    def read_uid(self):
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
                hresult, response = SCardTransmit(hcard,dwActiveProtocol,[0xFF,0xCA,0x00,0x00,0x04])
                uid = toHexString(response, format=0)
                print (uid)
            except SystemError:
                print ("No Card Found")
            time.sleep(1)

    def read_card_data(self):
        # Get Response
        try:
            print("Reading card data")
            self.hresult, self.response = SCardTransmit(self.hcard, self.dwActiveProtocol,[0xFF, 0xD6, 0x05, 0x09, 0x04])
            self.uid = toHexString(self.response, format=0)
            print (self.uid)
        except SystemError:
            print ("No Card Found")

    def write_card_data(self):
        # Direct Transmit
        WRITE = [0xFF, 0x00, 0xFF, 0x04, 0x0A, 0x0A, 0x03, 0x03]
        
    
        self.response, sw1 = SCardTransmit(self.hcard, self.dwActiveProtocol, COMMAND)

        if self.hresult != SCARD_S_SUCCESS:
            raise error, 'Failed to transmit: ' + SCardGetErrorMessage(self.hresult)
        else:
            print("Successful transmission")
            print(self.response)
            print(sw1)
            


if __name__ == '__main__':
    reader = NFC_Reader()
    reader.read_uid()
    reader.read_card_data()
    reader.write_card_data()
    reader.read_card_data()


