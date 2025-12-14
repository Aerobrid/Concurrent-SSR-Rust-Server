# Overview
This project is a  HTTP server built in Rust, originally featuring a thread pool for handling requests concurrently. It supports basic endpoints and provides server statistics. Based on the final project from The Rust Programming Language Book.

## Added Features
- **Thread Pool**: Efficiently handles multiple requests using a fixed number of worker threads.
- **Rate Limiting**: Limits requests per IP to prevent abuse.
- **Logging**: Logs requests and errors to a file.
- **Dynamic HTML Rendering**: Serves HTML pages for various endpoints.

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

## Endpoints
- **/**: Home page
- **/sleep**: Simulates a delay
- **/logs**: Displays server logs
- **/stats**: Shows server statistics

## Logging
Logs are written to `server.log`. Check this file for request logs and errors.

## Contributing
Feel free to submit issues or pull requests. Contributions are welcome!
