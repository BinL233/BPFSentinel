echo "[MAKE CLEAN]"
sudo make clean
echo

echo "[MAKE]"
sudo make
echo

echo "[Building BPF Programs]"
make clean
make

echo "[RUN ./scripts/run.sh]"
sudo ./scripts/run.sh
echo

echo "[RUN ./scripts/cleanup_tracing.sh]"
sudo ./scripts/cleanup_tracing.sh
echo
