import os
# NETMON_SUBNET is not set - let the scanner auto-detect all subnets
os.environ["NETMON_SCAN_TYPE"] = "scapy"

import uvicorn
uvicorn.run("main:app", host="127.0.0.1", port=8000)
