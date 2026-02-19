## Tracer
- Run setup script: `sudo ./setup.sh`
- Run tracers and targets: `cd ./src/tracer && sudo ./start.sh <your_interface>`
- Configuration: `./src/tracer/configs/config.json`
    - This file used to config target ebpf programs.
- Run `cd ./src/tracer && make vmlinux.h` if there's vmlinux dependency error.
- Tracers and targets will be automatically cleaned after terminating (`Ctrl+C`)


