import sys
sys.path.insert(0, '.')
from wifi_scanner import _scan_wifi_windows
result = _scan_wifi_windows()
print(f'Results: {len(result)}')
for r in result:
    ssid = r.get('ssid', '?')
    bssid = r.get('bssid', '?')
    sig = r.get('signal_percent', '?')
    ch = r.get('channel', '?')
    print(f'  {ssid} | {bssid} | {sig}% | Ch{ch}')
