# NFC_Reader
A general purpose NFC/RFID reader/writer with the ACR122U-A9 unit. 


## Installation && Run
1. `git clone git@github.com:SaundersB/NFC_Reader.git`
2. `python NFC_Reader.py`
3. Enjoy!

## Required Hardware
* [ACR122U-A9[(http://www.aliexpress.com/item/Free-Shipping-USB-ACR122U-NFC-RFID-Smart-Card-Reader-Writer-For-all-4-types-of-NFC/32276457920.html)
* 13.45MHz RFID Cards/Chips (ISO 14443-4A/B)


## Required Packages
* Download and install the Python [smartcard library](https://sourceforge.net/projects/pyscard/files/pyscard/]).
* Install the [ACR122U-A9 drivers](http://www.acs.com.hk/en/driver/3/acr122u-usb-nfc-reader/) for your system

## Usage
Use this program to interface between the ACR122U-A9 and an RFID card/chip. Connect your ACR122U-A9 and place an RFID card/chip in the bay. The LED light should light up green when the card is inserted into the bay. Change the string value in the main() to write specific values to the RFID card. 

## Intended Continual Work
I plan to continue to make this project more generalized so that it can be included in broader Python implementations. Additionally, I'd like to add event driven read/write of the cards with threading. 

## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## Credits

self.me = me

## License

MIT License

Copyright (c) 2016 Brandon Saunders

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
