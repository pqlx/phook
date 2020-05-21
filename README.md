# phook

`phook` attempts to provide an easy-to-use ptrace-backed function hooking solution for x86_64 linux. 

## Function hooking

Function hooking is the act of intercepting function calls and running alternative code instead of or before the existing function. 
This can be useful in a variety of scenarios. Think of debugging closed-source code, tracing function calls, et cetera. 


## Usage

As of now, `phook` only supports loading information from a JSON configuration file. An example configuration file as follows:

```json
{
    "target_executable": {
        "exec": ["test/build/target_dynamic", "arg1", "arg2"],
        "env": {
            "TEST_ENV": "A",
            "TEST_ENV_2": "B"
        }
    },
    "to_inject": "test/build/inject.so",
    "hooks": [
        
        {
            "target_offset": "target",
            "hook_offset": "hook",
            "mode": "detour"
        }
    ]

}
```

Every `target_offset` and `hook_offset` can be either a symbol, or a raw offset (hex strings allowed as well!).
The `mode` argument can take on a value of either `"replace"` (jump to hook and don't execute original function) or `"detour"` (resume execution), of which the latter will be selected automatically on omission. 

Generally, hooks of the type `replace` can only be used before the stack frame of the target function is set up. 


## Technical details

`phook` leverages the linux `ptrace` system call. This syscall allows processes to control other processes.

With this powerful functionality, `phook` first loads the library to be injected into the target's address space.
After this is done, `int3` instructions will be written to every specified hook target. Upon execution of such an `int3`, control will get delegated to `phook`,
on which we can change register state however we want.

An effort has been made to clearly document the `phook` code, and reading it is encouraged.

## Compilation

No strings attached, just run `./compile.sh`, and phook will be built. The resulting executable will be output to `./phook`.

To build the tests:

```bash
cd tests
./build_test.sh
```

## Usage

```
Usage: ./phook --config-file PATH-TO-CONFIG
```


## Planned features
As of now, phook is still a pretty simple and bare-bones project. It is not yet able to attach to an already running process,
and worse, cannot handle statically linked executables at all.

These features will most likely involve writing a custom dynamic loader. #WIP

