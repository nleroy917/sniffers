# sniffers
Basic file sniffer for detecting changes in files and directories, written in Rust.

## Usage
```python
from sniffers import Sniffer

sniffer = Sniffer()

# index a file or directory
sniffer.index()

# detect changes
changes = sniffer.sniff()

# print changes
for change in changes:
    print(change)
```

There also exists a command line interface for this package. You can use it as follows:
```bash
cargo build --release
./target/release/sniffers index
./target/release/sniffers sniff
```
