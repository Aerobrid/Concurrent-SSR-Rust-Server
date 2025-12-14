# Overview
This project is a  HTTP server built in Rust, originally featuring a thread pool for handling requests concurrently. It supports basic endpoints and provides server statistics. Based on the final project from The Rust Programming Language Book.

## Added Features
- **Thread Pool**: Efficiently handles multiple requests using a fixed number of worker threads.
- **Rate Limiting**: Limits requests per IP to prevent abuse (30 req/min, sliding window).
- **Request Timeout**: 5-second timeout prevents slowloris attacks.
- **Request Size Limit**: 8KB max prevents memory exhaustion.
- **Comprehensive Logging**: Logs requests with timestamps, IP, method, path, status, and response time.
- **Server Statistics**: Live stats on uptime, total requests, and average response time.
- **Dynamic HTML Rendering**: Server-side rendered pages with template substitution.
- **Atomic Operations**: Thread-safe stats using `AtomicU64` without race conditions.

## Setup and Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Aerobrid/Concurrent-SSR-Rust-Server
   cd Concurrent-SSR-Rust-Server
   ```

2. **Install Rust**:
   Ensure you have Rust installed. If not, you can install it using [rustup](https://rustup.rs/).

3. **Build the Project**:
   ```bash
   cargo build
   ```

4. **Run the Server**:
   ```bash
   cargo run
   ```
   The server will start running on `http://127.0.0.1:7878`.

## Testing

Run all tests (lib + main):
```bash
cargo test
```

Run only ThreadPool unit tests:
```bash
cargo test --lib
```

Run only server integration tests:
```bash
cargo test --test '*' -- --ignored
```

### Test Coverage
- **ThreadPool tests**: Creation, job execution, concurrency, panic on zero size
- **Server tests**: Rate limiting, HTTP parsing, error responses, atomic stats updates

## Documentation

View auto-generated Rust documentation:
```bash
cargo doc --open
```

This displays:
- ThreadPool API documentation
- Function signatures and doc comments
- Security considerations
- Implementation notes

## Endpoints
- **/**: Home page
- **/sleep**: Simulates a delay
- **/logs**: Displays server logs
- **/stats**: Shows server statistics

## Logging
Logs are written to `server.log`. Check this file for request logs and errors.

## Contributing
Feel free to submit issues or pull requests. Contributions are welcome!
