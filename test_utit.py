#-*-codeing:utf-8-*-
from byte_reader import byte_reader_object
import os
import sys


def main():

    bytes_data = b'\xd1\xc2\xb3\x40'
    reader = byte_reader_object(bytes_data)


    print(hex(reader.read_sleb_128())) 



if __name__  == "__main__":
    sys.exit(main())
    