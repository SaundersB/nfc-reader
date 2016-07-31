from smartcard.scard import *
from smartcard.util import toHexString
from smartcard.ATR import ATR
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
import time

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
        try:
            self.hresult, self.response = SCardTransmit(self.hcard, self.dwActiveProtocol,[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x10])
            self.uid = toHexString(self.response, format=0)
            print (self.uid)
        except SystemError:
            print ("No Card Found")

    def write_card_data(self):
        pass


if __name__ == '__main__':
    reader = NFC_Reader()
    reader.read_uid()

    reader.read_card_data()


