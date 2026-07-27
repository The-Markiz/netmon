@echo off
REM Collect ARP table from Windows host and write to shared volume for NetMon container.
REM Run this periodically or as a scheduled task.

set OUTPUT=%~dp0arp_table.json

:loop
echo [%time%] Collecting ARP table...
python -c "import json, subprocess, time; entries={}; r=subprocess.run(['arp','-a'],capture_output=True,text=True,timeout=5); lines=r.stdout.split('\n'); iface=''; [entries.update({p[0]:{'mac':p[1].replace('-',':').upper()}}) if len(p)>=3 and p[1]!='ff-ff-ff-ff-ff-ff' else None for line in lines if not line.strip().startswith('---') and not line.strip().startswith('Internet') for p in [line.split()] if line.strip() and not line.startswith('Interface')]; open(r'%OUTPUT%','w').write(json.dumps({'timestamp':time.time(),'count':len(entries),'entries':entries},indent=2)); print(f'{len(entries)} ARP entries saved')"

timeout /t 30 /nobreak >nul
goto loop
