## Backtick - A simple kdnet plugin for easier kernel debuggging

![Terminal demo](media/demo1.gif)

This project is a KDNET extension that enables reverse stepping at the kernel level by combining record/replay mechanisms with emulation techniques.

On top of that, we’ve built a (partially functional) TUI to make kd more user-friendly and visually appealing.

## Commands:
`!shadow` - Switch to emulation mode

`t- [n]` - Inverse Step (e.g. `t- 100`)

`!unshadow` - Switch to debugging mode


