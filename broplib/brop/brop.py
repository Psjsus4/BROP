class BROP(object):
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