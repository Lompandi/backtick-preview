## Backtick - A simple kdnet plugin for easier kernel debuggging

![Terminal demo](media/demo1.gif)

This project is a KDNET extension that enables reverse stepping at the kernel level by combining record/replay mechanisms with emulation techniques.

On top of that, we’ve built a (partially functional) TUI to make kd more user-friendly and visually appealing.

## Commands:
`!shadow` - Switch to emulation mode

`t- [n]` - Inverse Step (e.g. `t- 100`)

`!unshadow` - Switch to debugging mode


## Why Backtick?
- Function-ranged free stepping (can step backward or foward at any time).

- When debugging with kd, if the target machine trigger a kernel-mode exception,
the debugger will only be notice *after* `KeBugCheckEx` was called, but in shadow mode, you can trace every single instruction, for example, if the kernel-mode program trigger a access violation, the debugger will be notice after `KeBugCheckEx`
was called, however, in shadow mode, after single-stepping the access violation, you will end in `KiPageFault`, this allow a better understanding of the whole exception emit chanin.

- Fancy TUI.
