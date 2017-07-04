# python-moteannouncement
Python library for  moteannouncement protocol.

## Usage examples

```
from moteannouncement import DAReceiver
import time

address = 'sf@localhost:9002'
source = 0x0315     # address of the MURP on the gateway
receiver = DAReceiver(
    address=address,
    source=source,
    request_period=10
)

with receiver:
    receiver.query(
        "FFFFFFFFFFFF0610",
        query_types={"info": True, "description": True, "features": True}
    )
    while True:
        try:
            packet = receiver.poll()
        except KeyboardInterrupt:
            break
        else:
            if packet is not None:
                print(packet)
        time.sleep(0.01)
```
