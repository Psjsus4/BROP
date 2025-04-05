# BROPPER

<p align="center">
  An automatic Blind ROP exploitation python tool
  <br>
  <br>
</p>

## Flow of exploitation

1. Find buffer overflow offset
2. Find canary
3. Find saved registers (RBP / RIP)
4. Find stop gadgets
5. Find brop gadgets
6. Find a Write function (write / dprintf / puts / ...)
7. Leak the binary

## Script usage

To use this script:

```bash
python3 -m pip install -r requirements.txt
python3 bropper.py -t 127.0.0.1 -p 1337 --wait "Password :" --expected Bad --expected-stop Welcome -o dump
```

```bash
$ python3 bropper.py -h
usage: bropper.py [-h] -t TARGET -p PORT --expected-stop EXPECTED_STOP --expected EXPECTED --wait WAIT -o OUTPUT [--offset OFFSET] [--canary CANARY] [--no-canary] [--rbp RBP] [--rip RIP] [--stop STOP]
                  [--brop BROP] [--plt PLT] [--strcmp STRCMP] [--elf ELF]

Description message

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        target url
  -p PORT, --port PORT  target port
  --expected-stop EXPECTED_STOP
                        Expected response for the stop gadget
  --expected EXPECTED   Expected normal response
  --wait WAIT           String to wait before sending payload
  -o OUTPUT, --output OUTPUT
                        File to write dumped remote binary
  --offset OFFSET       set a offset value
  --canary CANARY       set a canary value
  --no-canary           Use this argument if there is no stack canary protection
  --rbp RBP             set rbp address
  --rip RIP             set rip address
  --stop STOP           set stop gadget address
  --brop BROP           set brop gadget address
  --plt PLT             set plt address
  --strcmp STRCMP       set strcmp entry value
  --elf ELF             set elf address
```
