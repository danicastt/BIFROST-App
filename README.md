## Technical Overview

This project implements a secure file encryption and transfer system in C# (.NET).

### Core Features

- RC6 block cipher (128-bit key, 20 rounds) in OFB stream mode
- Hybrid Bifid-OFB keystream scrambling layer
- Chunk-based streaming (64 KB blocks) for large file processing
- SHA-1 integrity verification embedded in JSON metadata header
- FileSystemWatcher-based automatic directory monitoring
- TCP client/server file transfer with streamed transmission
- Thread-safe logging system

### File Format

Each encrypted file contains:

1. 4-byte little-endian metadata length
2. UTF-8 JSON metadata header
3. Stream-encrypted payload

The metadata stores algorithm information, file properties, and SHA-1 integrity hash.
