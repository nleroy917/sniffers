# sniffers
Basic file sniffer for detecting changes in files and directories, written in Rust; complete with python bindings (of course).

## Installation
```bash
pip install sniffers
```

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

## Command Line Interface
There also exists a command line interface for this package.

To build and run the CLI, run the following commands:
```
cargo install --path .
```

Then, you can run the CLI as follows:

```bash
sniffers index
sniffers sniff
```
