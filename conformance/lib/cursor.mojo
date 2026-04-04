# conformance/lib/cursor.mojo


struct ByteWriter:
    var _buf: List[UInt8]
    var position: Int

    def __init__(out self, *, capacity: Int = 1500):
        self._buf = List[UInt8](capacity=capacity)
        self.position = 0

    def write_u8(mut self, value: UInt8) raises:
        self._buf.append(value)
        self.position += 1

    def write_u16_be(mut self, value: UInt16) raises:
        self.write_u8(UInt8((Int(value) >> 8) & 0xFF))
        self.write_u8(UInt8(Int(value) & 0xFF))

    def write_u32_be(mut self, value: UInt32) raises:
        self.write_u8(UInt8((Int(value) >> 24) & 0xFF))
        self.write_u8(UInt8((Int(value) >> 16) & 0xFF))
        self.write_u8(UInt8((Int(value) >> 8) & 0xFF))
        self.write_u8(UInt8(Int(value) & 0xFF))

    def write_u64_be(mut self, value: UInt64) raises:
        self.write_u32_be(UInt32((Int(value) >> 32) & 0xFFFFFFFF))
        self.write_u32_be(UInt32(Int(value) & 0xFFFFFFFF))

    def write_bytes(mut self, data: List[UInt8]) raises:
        for i in range(len(data)):
            self._buf.append(data[i])
        self.position += len(data)

    def finish(self) -> List[UInt8]:
        return self._buf.copy()


struct ByteReader:
    var _buf: List[UInt8]
    var position: Int

    def __init__(out self, data: List[UInt8]):
        self._buf = data.copy()
        self.position = 0

    def remaining(self) -> Int:
        return len(self._buf) - self.position

    def read_u8(mut self) raises -> UInt8:
        if self.remaining() < 1:
            raise "ByteReader: underflow reading u8"
        var v = self._buf[self.position]
        self.position += 1
        return v

    def read_u16_be(mut self) raises -> UInt16:
        if self.remaining() < 2:
            raise "ByteReader: underflow reading u16"
        var hi = UInt16(self._buf[self.position])
        var lo = UInt16(self._buf[self.position + 1])
        self.position += 2
        return (hi << 8) | lo

    def read_u32_be(mut self) raises -> UInt32:
        if self.remaining() < 4:
            raise "ByteReader: underflow reading u32"
        var result = UInt32(0)
        for i in range(4):
            result = (result << 8) | UInt32(self._buf[self.position + i])
        self.position += 4
        return result

    def read_u64_be(mut self) raises -> UInt64:
        if self.remaining() < 8:
            raise "ByteReader: underflow reading u64"
        var hi = UInt64(self.read_u32_be())
        var lo = UInt64(self.read_u32_be())
        return (hi << 32) | lo

    def read_bytes(mut self, n: Int) raises -> List[UInt8]:
        if self.remaining() < n:
            raise "ByteReader: underflow reading " + String(n) + " bytes"
        var result = List[UInt8]()
        for i in range(n):
            result.append(self._buf[self.position + i])
        self.position += n
        return result^
