set -e

TARGET_BIN="/Users/danielson/Documents/CMSC/414/buildit-breakit/break-it/6825f15e/bin"
DEMO_DIR="/tmp/buildit-demo"

pkill -f "$TARGET_BIN/router" 2>/dev/null || true
pkill -f "$TARGET_BIN/bank"   2>/dev/null || true
pkill -f "$TARGET_BIN/atm"    2>/dev/null || true
sleep 0.3

cleanup() {
    [ -n "$ROUTER_PID" ] && kill "$ROUTER_PID" 2>/dev/null || true
    [ -n "$BANK_PID" ]   && kill "$BANK_PID"   2>/dev/null || true
    [ -n "$ATM_PID" ]    && kill "$ATM_PID"    2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

rm -f bank.bank bank.atm Alice.card bank.in atm.in router.out bank.out atm.out

"$TARGET_BIN/init" bank

mkfifo bank.in atm.in

"$TARGET_BIN/router" > router.out 2>&1 &
ROUTER_PID=$!
disown
sleep 0.3

"$TARGET_BIN/bank" bank.bank < bank.in > bank.out 2>&1 &
BANK_PID=$!
disown

exec 9>bank.in

"$TARGET_BIN/atm" bank.atm < atm.in > atm.out 2>&1 &
ATM_PID=$!
disown
exec 8>atm.in

sleep 0.3

echo "create-user Alice 1234 5000" >&9
sleep 0.4

echo "begin-session Alice" >&8
sleep 0.2
echo "1234" >&8
sleep 0.5

echo "balance" >&8
sleep 0.5

echo "withdraw 1500" >&8
sleep 0.5

echo "balance" >&8
sleep 0.5

echo "withdraw 99999" >&8
sleep 0.5

echo "end-session" >&8
sleep 0.5

exec 9>&-
exec 8>&-
sleep 0.3
kill "$ROUTER_PID" "$BANK_PID" "$ATM_PID" 2>/dev/null || true
sleep 0.2

echo
echo "  WHAT THE LEGITIMATE USER SAW (atm)"
cat atm.out
echo
echo "  WHAT THE BANK SAW"
cat bank.out
echo
echo "  WHAT THE ATTACKER LEARNED (malicious router)"
cat router.out
