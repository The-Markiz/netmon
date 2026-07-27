import subprocess
result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], capture_output=True, text=True, encoding='cp866', errors='replace')
lines = result.stdout.split('\n')
current_ssid = ''
current = {}
networks = []
for line in lines:
    line = line.strip()
    if not line:
        continue
    if line.startswith('SSID') and 'BSSID' not in line and ':' in line:
        current_ssid = line.split(':', 1)[1].strip()
        continue
    if line.startswith('BSSID') and ':' in line:
        if current.get('ssid') and current.get('bssid'):
            networks.append(current)
        current = {'ssid': current_ssid, 'bssid': line.split(':', 1)[1].strip()}
        continue
    if line.startswith('Signal') and ':' in line:
        try:
            pct = int(line.split(':', 1)[1].strip().replace('%', ''))
            current['signal_percent'] = pct
        except:
            pass
    elif line.startswith('Channel') and ':' in line:
        current['channel'] = line.split(':', 1)[1].strip()
    elif line.startswith('Radio type') and ':' in line:
        current['radio_type'] = line.split(':', 1)[1].strip()
    elif line.startswith('Band') and ':' in line:
        current['band'] = line.split(':', 1)[1].strip()
if current.get('ssid') and current.get('bssid'):
    networks.append(current)
print(f'Total networks: {len(networks)}')
for n in networks:
    ssid = n.get('ssid', '?')
    bssid = n.get('bssid', '?')
    sig = n.get('signal_percent', '?')
    ch = n.get('channel', '?')
    print(f'  {ssid} | {bssid} | {sig}% | Ch{ch}')
