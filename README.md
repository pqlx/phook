# phook

`phook` attempts to provide a ptrace-backed function hooking solution for linux.

## Function hooking

Function hooking is the act of intercepting function calls and running alternative code instead of or before the existing function. 
This can be useful in a variety of scenarios. Think of debugging closed-source code, tracing function calls, et cetera.

## Usage

As of now, `phook` only supports loading information from a configuration file. The format of this configuration file will be documented at a later date.

```
phook --config ./config.json
```


## Compilation

No strings attached, just run `./compile.sh`, and phook will be built. The resulting executable will be output to `./phook`.
