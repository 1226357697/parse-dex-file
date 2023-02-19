#-*- coding:utf-8 -*-

from byte_reader import byte_reader_object
from enum import Enum
class class_access_flags(Enum):
    ACC_PUBLIC       = 0x00000001       # class, field, method, ic
    ACC_PRIVATE      = 0x00000002       # field, method, ic
    ACC_PROTECTED    = 0x00000004       # field, method, ic
    ACC_STATIC       = 0x00000008       # field, method, ic
    ACC_FINAL        = 0x00000010       # class, field, method, ic
    ACC_SYNCHRONIZED = 0x00000020       # method (only allowed on natives)
    ACC_SUPER        = 0x00000020       # class (not used in Dalvik)
    ACC_VOLATILE     = 0x00000040       # field
    ACC_BRIDGE       = 0x00000040       # method (1.5)
    ACC_TRANSIENT    = 0x00000080       # field
    ACC_VARARGS      = 0x00000080       # method (1.5)
    ACC_NATIVE       = 0x00000100       # method
    ACC_INTERFACE    = 0x00000200       # class, ic
    ACC_ABSTRACT     = 0x00000400       # class, method, ic
    ACC_STRICT       = 0x00000800       # method
    ACC_SYNTHETIC    = 0x00001000       # field, method, ic
    ACC_ANNOTATION   = 0x00002000       # class, ic (1.5)
    ACC_ENUM         = 0x00004000       # class, field, ic (1.5)
    ACC_CONSTRUCTOR  = 0x00010000       # method (Dalvik only)
    ACC_DECLARED_SYNCHRONIZED = 0x00020000       # method (Dalvik only)
    ACC_CLASS_MASK = (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM)
    ACC_INNER_CLASS_MASK = (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC)
    ACC_FIELD_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM)
    ACC_METHOD_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
                        | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
                        | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
                        | ACC_DECLARED_SYNCHRONIZED)

class dex_string_id_info(object):
    def __init__(self, offset, string) -> None:
        self.offset = offset
        self.string = string

class dex_type_id_info(object):
    def __init__(self, id, string) -> None:
        self.id = id
        self.string = string

class dex_proto_id_info(object):
    def __init__(self, shorty_string:str, return_type:str, parameter:list) -> None:
        self.shorty_string:str  = shorty_string
        self.return_type:str = return_type
        self.parameter_list:list(str) = parameter

class dex_field_id_info(object):
    def __init__(self, class_name:str, type_name:str, field_name) -> None:
        self.class_name:str  = class_name
        self.type_name:str = type_name
        self.field_name:str = field_name

class dex_method_id_info(object):
    def __init__(self, class_name:str, proto_info:dex_proto_id_info, method_name) -> None:
        self.class_name:str  = class_name
        self.proto_info:dex_proto_id_info = proto_info
        self.method_name:str = method_name

class dex_filed_info(object):
    def __init__(self, filed, access_flags) -> None:
        self.type:dex_field_id_info = filed
        self.access_flags:class_access_flags = access_flags

class dex_code_info(object):
    def __init__(self) -> None:
        self.registers_size
        self.ins_size
        self.outs_size
        self.tries_size
        self.debug_info_off
        self.inns_size
        self.inns:bytes


class dex_method_info(object):
    def __init__(self, method:dex_method_id_info, access_flags:class_access_flags, code) -> None:
        self.method:dex_method_id_info = method
        self.access_flags:class_access_flags = access_flags

class dex_class_data(object):
    def __init__(self, static_field_size:int, instance_field_size:int, direct_methods_size:int,  virtual_method_size:int, 
                    static_fields:list, instance_fields:list, direct_methods:list,  virtual_methods:list) -> None:
        self.static_field_size:int = static_field_size
        self.instance_field_size:int = instance_field_size
        self.direct_methods_size:int = direct_methods_size
        self.virtual_method_size:int = virtual_method_size
        self.static_fields:list = static_fields
        self.instance_fields:list = instance_fields
        self.direct_methods:list = direct_methods
        self.virtual_methods:list = virtual_methods

class dex_calss_def_info(object):
    def __init__(self, class_type:str, access_flags:class_access_flags, super_calss_type:str, interfaces:list, source_file:str, 
                    annotation:None, class_data:dex_class_data, static_value:None) -> None:
        self.calss_type:str = class_type
        self.access_flags:class_access_flags = access_flags
        self.super_class_type:str = super_calss_type
        self.interfaces:list = interfaces
        self.source_file:str = source_file
        self.annotation:None = annotation
        self.class_data:dex_class_data = class_data
        self.static_value:None = static_value

class DexFile(object):
    def __init__(self, byte_data:bytes) -> None:
        self.reader = byte_reader_object(byte_data)
        self.__origin_data = byte_data
        self.__initialize()

    def __initialize(self):
        self.reader.setpos(0x20)
        self.__file_size = self.reader.read_u4()
        self.reader.setpos(0x34)
        self.__mapoff = self.reader.read_u4()
        self.__str_id_size = self.reader.read_u4()
        self.__str_id_off = self.reader.read_u4()
        self.__type_id_size = self.reader.read_u4()
        self.__type_id_off = self.reader.read_u4()        
        self.__proto_id_size = self.reader.read_u4()
        self.__proto_id_off = self.reader.read_u4()      
        self.__field_id_size = self.reader.read_u4()
        self.__field_id_off = self.reader.read_u4()    
        self.__method_id_size = self.reader.read_u4()
        self.__method_id_off = self.reader.read_u4()    
        self.__class_def_size = self.reader.read_u4()
        self.__class_def_off = self.reader.read_u4()       
        self.__data_id_size = self.reader.read_u4()
        self.__data_id_off = self.reader.read_u4()       

        self.string_id_pool:list = [] # dex_string_id_info
        self.type_id_pool:list = [] # dex_type_id_info
        self.proto_id_pool:list = [] # dex_proto_id_info
        self.field_id_pool:list = [] # dex_field_id_info
        self.method_id_pool:list = [] # dex_method_id_info
        self.class_def_pool:list = [] # dex_calss_def_info
        self.__parse_string_id()
        self.__parse_type_id()
        self.__parse_proto_id()
        self.__parse_field_id()
        self.__parse_method_id()
        self.__parse_class_def()

    def __parse_string_id(self):
        str_reader = byte_reader_object(self.__origin_data[self.__str_id_off : self.__str_id_off + (self.__str_id_size * 4)])

        for i in range(self.__str_id_size) :
            str_off = str_reader.read_u4()
            char_count = int().from_bytes(self.__origin_data[str_off:str_off+1], 'little')
            byte = self.__origin_data[str_off + 1:str_off + 1 + char_count]
            self.string_id_pool.append(dex_string_id_info(str_off, byte.decode('utf-8',  'backslashreplace')))

    def __parse_type_id(self):
        str_reader = byte_reader_object(self.__origin_data[self.__type_id_off : self.__type_id_off + (self.__type_id_size * 4)])

        if len(self.string_id_pool) == 0:
            self.__parse_string_id()

        for i in range(self.__type_id_size) :
            str_id = str_reader.read_u4()
            self.type_id_pool.append(dex_type_id_info(str_id, self.string_id_pool[str_id].string))
    
    def __parse_proto_id(self):
        proto_reader = byte_reader_object(self.__origin_data[self.__proto_id_off : self.__proto_id_off + (self.__proto_id_size * 0xc)])

        for i in range(self.__proto_id_size):
            shortyidx = proto_reader.read_u4()
            return_type_index = proto_reader.read_u4()
            parameters_offset = proto_reader.read_u4()

            self.proto_id_pool.append(dex_proto_id_info(self.string_id_pool[shortyidx].string,  self.type_id_pool[return_type_index].string, self.__get_param_type_list(parameters_offset)))

    def __get_param_type_list(self, parameters_offset)-> list: 
        type_list_pool = []
        
        if parameters_offset != 0:

            self.reader.setpos(parameters_offset)
            type_list_size = self.reader.read_u4()

            type_list_reader = byte_reader_object(self.__origin_data[self.reader.pos() : self.reader.pos() + (type_list_size * 2)])

            if len(self.type_id_pool) == 0:
                self.__parse_type_id()

            for i in range(type_list_size):
                type_id = type_list_reader.read_u2()

                type_list_pool.append(self.type_id_pool[type_id].string)

        return type_list_pool

    def __parse_field_id(self) :
        field_reader = byte_reader_object(self.__origin_data[self.__field_id_off : self.__field_id_off + (self.__field_id_size * 8) ])

        for i in range(self.__field_id_size):
            class_id = field_reader.read_u2()
            type_id = field_reader.read_u2()
            name_id = field_reader.read_u4()

            self.field_id_pool.append(dex_field_id_info(self.type_id_pool[class_id].string, self.type_id_pool[type_id].string, self.string_id_pool[name_id].string))

    def __parse_method_id(self):
        method_reader = byte_reader_object(self.__origin_data[self.__method_id_off : self.__method_id_off + (self.__method_id_size * 8) ])

        for i in range(self.__method_id_size):
            class_id = method_reader.read_u2()
            proto_id = method_reader.read_u2()
            name_id = method_reader.read_u4()

            self.method_id_pool.append(dex_method_id_info(self.type_id_pool[class_id].string, self.proto_id_pool[proto_id], self.string_id_pool[name_id].string))

    def __get_filed_list(self, offset, size)->dex_filed_info:

        if size == 0 :
            return None

        field_reader = byte_reader_object(self.__origin_data[offset : offset + (size * 8) ])

        field_id = field_reader.read_uleb_128()
        access_falgs = field_reader.read_uleb_128()

        return dex_filed_info(self.field_id_pool[field_id], access_falgs)

    def __get_method_list(self, offset, size)->dex_method_info:

        if size == 0 :
            return None

        method_reader = byte_reader_object(self.__origin_data[offset : offset + (size * 8) ])

        method_id = method_reader.read_uleb_128()
        access_falgs = method_reader.read_uleb_128()

        return dex_method_info(self.method_id_pool[method_id], access_falgs, None) 

    def __parse_class_data(self, offset)->dex_class_data:
        self.reader.setpos(offset)
        static_field_size:int = self.reader.read_uleb_128()
        instance_field_size:int = self.reader.read_uleb_128()
        direct_methods_size:int = self.reader.read_uleb_128()
        virtual_method_size:int = self.reader.read_uleb_128()

        static_fields:list = self.__get_filed_list(self.reader.pos(), static_field_size)
        instance_fields:list = self.__get_filed_list(self.reader.pos(), instance_field_size)
        direct_methodss:list = self.__get_method_list(self.reader.pos(), direct_methods_size)
        virtual_methods:list = self.__get_method_list(self.reader.pos(), virtual_method_size)

        return dex_class_data(  static_field_size,
                                instance_field_size,
                                direct_methods_size,
                                virtual_method_size,
                                static_fields,
                                instance_fields,
                                direct_methodss,
                                virtual_methods)

    def __parse_class_def(self):
        class_reader = byte_reader_object(self.__origin_data[self.__class_def_off : self.__class_def_off + (self.__class_def_size * (8 * 4))])

        for i in range(self.__class_def_size):
            class_id = class_reader.read_u4()
            access_flags = class_reader.read_u4()
            super_class_id = class_reader.read_u4()
            interfaces_off = class_reader.read_u4()
            source_file_id = class_reader.read_u4()
            annotations_off = class_reader.read_u4()
            class_data_off = class_reader.read_u4()
            static_value_off = class_reader.read_u4()

            self.class_def_pool.append(dex_calss_def_info(self.type_id_pool[class_id], 
                                                            access_flags, 
                                                            self.type_id_pool[super_class_id],
                                                            self.__get_param_type_list(interfaces_off),
                                                            self.string_id_pool[source_file_id],
                                                            None,
                                                            self.__parse_class_data(class_data_off),
                                                            None  ))


    def __pretty_base_type_name(self, base_name:str)->str:
        base_type_map = {'B' : 'byte', 'C' : 'char', 'D' : 'double', 'F' : 'float', 'I' : 'int', 'J' : 'long'}
        array_prefix = ''
        toal_count = base_name.count('[')

        if toal_count != 0 :
            array_prefix = '[' * toal_count

            if base_name.startswith(array_prefix) :
                base_name = base_name[toal_count:]

        if base_name in base_type_map:
                base_name = base_type_map[base_name]
        
        return array_prefix + base_name

    def show_all_string(self):
        idx = 0
        for string_info in self.string_id_pool:
            print('index: {0} offset: {1} string: {2}'.format(hex(idx),hex(string_info.off), string_info.string))
            idx = idx + 1

    def show_all_type_string(self):
        for type_info in self.type_id_pool:
            print('index: {0} type string: {1}'.format(hex(type_info.id), self.__pretty_base_type_name(type_info.string)))

    def show_all_shorty_proto(self):
        for proto_info in self.proto_id_pool:
            print('proto shorty: {0}'.format(proto_info.shorty_string))

    def show_all_field_string(self):
        for field_info in self.field_id_pool:
            print('field: {0} {1} {2}'.format(field_info.class_name, self.__pretty_base_type_name(field_info.type_name) , field_info.field_name))

    def show_all_method_string(self):
        for method_info in self.method_id_pool:
            print('method: {0} {1} {2}'.format(method_info.class_name, method_info.proto_info.shorty_string , method_info.method_name))            

    def show_all_class_info(self):
        for class_def in self.class_def_pool:
            print('class name: {0}'.format(class_def.calss_type.string))

    def file_size(self) :
        return self.__file_size
    
    def is_valid(self) : 
        self.reader.setpos(0)
        return b'\x64\x65\x78\x0a\x30\x33\x35\x00' == self.reader.read(8)

