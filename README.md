## Tracer
- Run tracers and targets: `sudo ./src/tracer/start.sh`
- Configuration: `./src/tracer/configs/config.json`
    - This file used to config target ebpf programs.
- Run `make vmlinux.h` if there's vmlinux dependency error.
- Tracers and targets will be automatically cleaned after terminating (`Ctrl+C`)


