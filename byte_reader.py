# -*-coding:utf-8 -*-


class byte_reader_object(object):
    def __init__(self, byte_data:bytes) -> None:
        self.data:bytes = byte_data
        self.index = 0
    
    def reset(self) :
        self.index = 0
    
    def setpos(self, pos) : 
        self.index = pos

    def pos(self):
        return self.index

    def eop(self)->bool: 
        return self.index == len(self.data)

    def read_mutf8(self)->str:
        pass

    def read(self, size) : 
        stub = self.data[self.index : self.index + size]
        self.index = self.index + size
        return stub

    def read_u1(self) -> int: 
        u1 = int().from_bytes(self.data[self.index : self.index + 1], "little") 
        self.index  = self.index + 1
        return u1
    
    def read_u2(self) -> int: 
        u2 = int().from_bytes(self.data[self.index : self.index + 2], "little") 
        self.index = self.index + 2
        return u2

    def read_u4(self) -> int: 
        u4 = int().from_bytes(self.data[self.index : self.index + 4], "little") 
        self.index = self.index + 4
        return u4

    def read_u8(self) -> int: 
        u8 = int().from_bytes(self.data[self.index : self.index + 8], "little")   
        self.index = self.index  + 8
        return  u8

    def read_uleb_128(self) ->int:
        result = self.read_u1()
        if result > 0x7f :
            cur = self.read_u1()
            result = (result & 0x7f) | ((cur & 0x7f) << 7)
            if cur > 0x7f :
                cur = self.read_u1()
                result = result | ((cur & 0x7f) << 14)
                if cur > 0x7f :
                    cur = self.read_u1()
                    result = result | ((cur & 0x7f) << 21)
                    if cur > 0x7f :
                        cur = self.read_u1()
                        result = result | ((cur & 0x7f) << 28)                    
        return result

    def __bit32_signed_extend(self, data:int):
        return ((0xffffffff >> data.bit_length() ) <<  data.bit_length()) | data 

    def read_sleb_128(self) ->int:
        result = self.read_u1()
        if result <= 0x7f:
            # result = (result << 25) >> 25
            result = self.__bit32_signed_extend(result)
        else:
            cur = self.read_u1()
            result = (result & 0x7f) | ((cur & 0x7f) << 7)
            if cur <= 0x7f:
                #result = (result << 18) >> 18
                result = self.__bit32_signed_extend(result)
            else:
                cur = self.read_u1()
                result = result | ((cur & 0x7f) << 14)
            if cur <= 0x7f:
                #result = (result << 11) >> 11
                result = self.__bit32_signed_extend(result)
            else:    
                cur = self.read_u1()
                result = result | ((cur & 0x7f) << 21)
                if cur <= 0x7f:
                    #result = (result << 4) >> 4
                    result = self.__bit32_signed_extend(result)
                else:    
                    cur = self.read_u1()
                    result = result | (cur << 28)
                      
        return result        
    
    def read_uleb_128_p1(self)->int:
        return self.read_uleb_128() + 1