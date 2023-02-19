# -*- coding: UTF-8 -*-

import sys
from parse_dex import DexFile


def main() :
    with open('./classes.dex', 'rb') as fi:
        byte_data =  fi.read()
        print(byte_data.__class__.__name__)

        dex_file = DexFile(byte_data)

        
        # dex_file.show_all_string() # display all string for dex

        # dex_file.show_all_type_string()
        
        # dex_file.show_all_shorty_proto()

        # dex_file.show_all_field_string()

        # dex_file.show_all_method_string()

        dex_file.show_all_class_info()



        print("overt")


if __name__ == "__main__":
    sys.exit(main())