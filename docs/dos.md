# DoS Modules (10)

Denial-of-service / resource-exhaustion modules. Path: `modules/dos/`.

> ⚠️ DoS modules disrupt the target. Run only against equipment you own or have explicit written authorization to test.

| Module | Technique |
|---|---|
| `bluesmack` | Oversized L2CAP echo (classic "ping of death") |
| `l2ping_flood` | Sustained `l2ping` flood |
| `a2dp_flood` | A2DP packet flood — saturates audio profile |
| `notify_flood` | GATT notification flood |
| `sdp_flood` | SDP service-record flood |
| `rfcomm_flood` | RFCOMM session flood |
| `rfcomm_msc_flood` | RFCOMM MSC frame flood |
| `rfcomm_state_change_deadlock` | Forces RFCOMM state-change deadlock |
| `rfcomm_check_security_null` | NULL-deref on RFCOMM security check |
| `xiaomi_rfcomm_dlci_flood` | Xiaomi-specific DLCI flood |

---

## Common options

| Option | Meaning |
|---|---|
| `TARGET` | Target MAC |
| `IFACE` | Local HCI device |
| `COUNT` | Packets to send (`0` = unlimited) |
| `INTERVAL` | Delay between packets (seconds) |
| `SIZE` | Payload size (where applicable) |

---

## Example

```text
bluesploit > use dos/bluesmack
bluesploit(dos/bluesmack) > set TARGET AA:BB:CC:DD:EE:FF
bluesploit(dos/bluesmack) > set SIZE 600
bluesploit(dos/bluesmack) > run
```
