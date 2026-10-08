"""SQ 授权系统 Python SDK（``docs/SDK-PYTHON.md``）。

```python
from sdk import LicenseClient

client = LicenseClient("https://license.example.com", RESPONSE_PUBLIC_KEY)
client.activate("GSQ-XXXXX-XXXXX-XXXXX-XXXXX")
if client.is_valid():
    ...
```
"""

from .sq_license_client import (
    LicenseClient,
    LicenseError,
    LicenseSignatureError,
    LicenseTransportError,
)

__all__ = [
    "LicenseClient",
    "LicenseError",
    "LicenseSignatureError",
    "LicenseTransportError",
]

__version__ = "1.0.0"
