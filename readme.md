3-3-2026
this is a ida script for mac to dump decompile code from idat64

without open ida

run 
```
/babytcache> bash ../../../tools/auto_script.sh --binary ./babytcache --out ./export_chall

[*] IDA : /Applications/IDA Professional 9.0.app/Contents/MacOS/idat64
[*] BIN : /Users/xxx/Desktop/rev-pwn-agent-self-study/ctf_archive/backdoorctf2019/babytcache/babytcache
[*] OUT : /Users/xxx/Desktop/rev-pwn-agent-self-study/ctf_archive/backdoorctf2019/babytcache/export_chall
[*] DB  : /Users/xxx/Desktop/rev-pwn-agent-self-study/ctf_archive/backdoorctf2019/babytcache/export_chall/babytcache.i64
[*] LOG : /Users/xxx/Desktop/rev-pwn-agent-self-study/ctf_archive/backdoorctf2019/babytcache/export_chall/ida_export.log
[*] PY  : /Users/xxx/Desktop/rev-pwn-agent-self-study/tools/auto_ida_export.py
[*] Running checksec...
```

final can see
```
~/D/r/c/b/b/export_chall> ls
babytcache.i64
babytcache_export
checksec.txt
ida_export.log


~/D/r/c/b/b/e/babytcache_export> ls
call_graph.txt
decompile <---- here is the decompile code
exports.txt
functions.json <---- here is the static analysed code brief result
imports.txt
memory
strings.txt

under decompile
0x7c0__init_proc.c
0x7e0_sub_7E0.c

under memory
00000000--000007C0.txt
```

