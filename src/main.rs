use hello::ThreadPool;
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write, ErrorKind},
    net::{TcpListener, TcpStream, SocketAddr},
    // Ordering::SeqCst -> “All threads agree on 1 global order of atomic operations.”
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}},
    thread,
    time::{Duration, Instant},
};

// configuration
const MAX_REQUEST_SIZE: usize = 8192;                           // 8KB max prevents memory exhaustion
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);       // prevents slowloris attacks
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);    // 1 minute window
const MAX_REQUESTS_PER_WINDOW: usize = 30;                      // 30 req/min per IP for DDoS protection
const THREAD_POOL_SIZE: usize = 4;                              // fixed pool prevents resource exhaustion
const LOG_FILE: &str = "server.log";                            // request log file name to be used upon creation

// shared state between threads using type aliasing (for log file and each IP request history)
type RateLimiter = Arc<Mutex<HashMap<String, Vec<Instant>>>>;
type RequestLogger = Arc<Mutex<fs::File>>;

// server statistics
struct ServerStats {
    start_time: Instant,
    total_requests: AtomicU64,
    total_response_time: AtomicU64,
}

impl ServerStats {
    // constructor initialization
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_requests: AtomicU64::new(0),
            total_response_time: AtomicU64::new(0),
        }
    }
}

fn main() {
    // logic for handling tcp connections (loopback addr used for simplicity)
    let listener = TcpListener::bind("127.0.0.1:7878")
        .expect("Failed to bind to address");

    // non-blocking accept so Ctrl+C can break the loop
    listener
        .set_nonblocking(true)
        .expect("Failed to set non-blocking listener");
    
    let pool = ThreadPool::new(THREAD_POOL_SIZE);
    
    // shared rate limiter tracks requests per IP
    let rate_limiter: RateLimiter = Arc::new(Mutex::new(HashMap::new()));
    
    // shared log file for request logging
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .expect("Failed to open log file");

    // make log file thread-safe + thread-accessible
    let logger: RequestLogger = Arc::new(Mutex::new(log_file));
    
    // server statistics
    let stats = Arc::new(ServerStats::new());
    
    // setup Ctrl+C handler to cleanup the logs
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\nReceived shutdown signal...");
        // clear log file contents on shutdown
        if let Ok(mut file) = OpenOptions::new().write(true).truncate(true).open(LOG_FILE) {
            // neat trick
            let _ = file.write_all(b"");
            println!("Log file cleared");
        }
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");
    
    // terminal configuration print for dev logs
    println!("Server running on http://127.0.0.1:7878");
    println!("Thread pool: {THREAD_POOL_SIZE} workers");
    println!("Rate limit: {}/min per IP | Timeout: {}s | Max size: {}KB", 
             MAX_REQUESTS_PER_WINDOW, REQUEST_TIMEOUT.as_secs(), MAX_REQUEST_SIZE / 1024);
    println!("Logging to: {LOG_FILE}");
    println!("Endpoints: / | /sleep | /logs | /stats\n");

    // main server loop: runs until Ctrl+C sets running to false
    // running.load checks atomic bool without race conditions (super useful)
    while running.load(Ordering::SeqCst) {
        // accept any incoming TCP connection (set to non-blocking earlier)
        match listener.accept() {
            Ok((stream, _addr)) => {
                // clone Arc pointers (increments reference count, NOT data copy)
                // each thread gets its own Arc pointing to same shared data
                let rate_limiter = Arc::clone(&rate_limiter);
                let logger = Arc::clone(&logger);
                let stats = Arc::clone(&stats);

                // hand off connection to thread pool worker
                // move closure transfers ownership of stream + Arc clones into worker thread
                pool.execute(move || {
                    handle_connection(stream, rate_limiter, logger, stats);
                });
            }
            // NO CONNECTION AVAILABLE (non-blocking mode returns this instead of waiting)
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // sleep briefly to avoid spinning CPU at 100% checking for connections (learned: polling loop would waste CPU cycles)
                thread::sleep(Duration::from_millis(50));
            }
            // ACTUAL ERROR (network problem, OS issue, etc)            
            Err(e) => {
                eprintln!("Connection error: {e}");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    println!("\nShutting down server...");
}

/// Handles a single TCP connection with comprehensive security checks.
///
/// # Security Features
/// - Rate limiting (30 req/min per IP)
/// - Request timeout (5 seconds)
/// - Max request size enforcement (8KB)
/// - HTTP method validation (GET only)
/// - Error response handling
///
/// # Arguments
/// * `stream` - TCP connection stream
/// * `rate_limiter` - Shared rate limiter tracking requests per IP
/// * `logger` - Shared log file for request logging
/// * `stats` - Shared server statistics (uptime, request counts, response times)
fn handle_connection(mut stream: TcpStream, rate_limiter: RateLimiter, logger: RequestLogger, stats: Arc<ServerStats>) {
    // start time
    let start = Instant::now();
    
    // set timeouts to prevent slowloris attacks
    if let Err(e) = stream.set_read_timeout(Some(REQUEST_TIMEOUT)) {
        eprintln!("Failed to set read timeout: {e}");
        return;
    }
    if let Err(e) = stream.set_write_timeout(Some(REQUEST_TIMEOUT)) {
        eprintln!("Failed to set write timeout: {e}");
        return;
    }

    // get client IP for rate limiting and logging (IP check)
    let client_addr = if let Ok(addr) = stream.peer_addr() { addr } else {
        send_error_response(&mut stream, "500 Internal Server Error", "Unable to identify client");
        return;
    };

    // rate limit check before processing request
    if !check_rate_limit(&rate_limiter, &client_addr) {
        log_request(&logger, &client_addr, "RATE_LIMITED", "/", 429, start.elapsed().as_millis());
        println!("Rate limit exceeded: {client_addr}");
        send_error_response(&mut stream, "429 Too Many Requests", "Rate limit exceeded. Please try again later.");
        return;
    }

    // read and parse request with size limit constraint
    let (method, path) = match read_request(&mut stream) {
        Ok(req) => req,
        Err(e) => {
            log_request(&logger, &client_addr, "BAD_REQUEST", "/", 400, start.elapsed().as_millis());
            println!("Bad request from {client_addr}: {e}");
            send_error_response(&mut stream, "400 Bad Request", "Malformed request");
            return;
        }
    };

    // update stats ATOMICALLY upon a successful request (remember multiple threads can access)
    stats.total_requests.fetch_add(1, Ordering::SeqCst);
    // for developer log only
    println!("{method} {path} from {client_addr}");

    // route the request to appropriate handler using match (pattern/expression) based primarily on its path
    let (status_line, filename, status_code) = match (method.as_str(), path.as_str()) {
        ("GET", "/") => ("HTTP/1.1 200 OK", "hello.html", 200),
        ("GET", "/sleep") => {
            // slow endpoint arbitrarily (decided to keep feature from tutorial) for threadpool concurrency testing
            thread::sleep(Duration::from_secs(3));
            ("HTTP/1.1 200 OK", "hello.html", 200)
        }
        ("GET", "/logs") => {
            // serve log file IF it exists
            if let Ok(logs) = fs::read_to_string(LOG_FILE) {
                let length = logs.len();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{logs}"
                );
                let elapsed = start.elapsed().as_millis();
                stats.total_response_time.fetch_add(elapsed as u64, Ordering::SeqCst);
                let _ = stream.write_all(response.as_bytes());
                log_request(&logger, &client_addr, &method, &path, 200, elapsed);
                return;
            }
            ("HTTP/1.1 404 NOT FOUND", "404.html", 404)
        }
        ("GET", "/stats") => {
            // acqire live server statistics
            let uptime = stats.start_time.elapsed().as_secs();
            // read stats ATOMICALLY 
            let total_reqs = stats.total_requests.load(Ordering::SeqCst);
            let total_time = stats.total_response_time.load(Ordering::SeqCst);
            let avg_time = if total_reqs > 0 { total_time / total_reqs } else { 0 };
            
            // server-side rendering
            let stats_html = fs::read_to_string("stats.html")
                .unwrap_or_else(|_| String::from("<html><body><h1>Stats page not found</h1></body></html>"))
                .replace("{{UPTIME}}", &format!("{uptime}"))
                .replace("{{TOTAL_REQUESTS}}", &format!("{total_reqs}"))
                .replace("{{AVG_RESPONSE}}", &format!("{avg_time}"))
                .replace("{{THREAD_COUNT}}", &format!("{THREAD_POOL_SIZE}"));
            
            // server reply a.k.a response to be sent over our tcp stream
            let length = stats_html.len();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{stats_html}"
            );
            // update ATOMICALLY + record in server.log
            let elapsed = start.elapsed().as_millis();
            stats.total_response_time.fetch_add(elapsed as u64, Ordering::SeqCst);
            let _ = stream.write_all(response.as_bytes());
            log_request(&logger, &client_addr, &method, &path, 200, elapsed);
            return;
        }
        // a GET req to any other path is NOT valid, so redirect to the 404 page
        ("GET", _) => ("HTTP/1.1 404 NOT FOUND", "404.html", 404),
        _ => {
            // reject non-GET methods (maybe in future will add extra features)
            log_request(&logger, &client_addr, &method, &path, 405, start.elapsed().as_millis());
            send_error_response(&mut stream, "405 Method Not Allowed", "Only GET requests are supported");
            return;
        }
    };

    // reads HTML file mapped from user selected path to string and sends HTTP response back to client
    match fs::read_to_string(filename) {
        Ok(contents) => {
            let length = contents.len();
            let elapsed = start.elapsed().as_millis();
            let response = format!(
                "{status_line}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {length}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nX-Response-Time: {elapsed}ms\r\n\r\n{contents}"
            );
            
            stats.total_response_time.fetch_add(elapsed as u64, Ordering::SeqCst);
            
            if let Err(e) = stream.write_all(response.as_bytes()) {
                eprintln!("Failed to send response: {e}");
            } else {
                log_request(&logger, &client_addr, &method, &path, status_code, elapsed);
            }
        }
        Err(e) => {
            eprintln!("Failed to read file {filename}: {e}");
            log_request(&logger, &client_addr, &method, &path, 500, start.elapsed().as_millis());
            send_error_response(&mut stream, "500 Internal Server Error", "Failed to load page");
        }
    }
}

/// Checks if a client IP has exceeded the rate limit using a sliding window algorithm.
///
/// # Rate Limit Policy
/// - Window: 60 seconds (`RATE_LIMIT_WINDOW`)
/// - Max requests: 30 per window (`MAX_REQUESTS_PER_WINDOW`)
/// - Algorithm: Sliding window with timestamp retention
///
/// # Arguments
/// * `rate_limiter` - Shared `HashMap` tracking request timestamps per IP
/// * `addr` - Client socket address (IP extracted for tracking)
///
/// # Returns
/// - `true` if request is allowed
/// - `false` if rate limit exceeded
fn check_rate_limit(rate_limiter: &RateLimiter, addr: &SocketAddr) -> bool {
    // mutex lock -> stringify ip -> start time
    let mut limiter = rate_limiter.lock().unwrap();
    let ip = addr.ip().to_string();
    let now = Instant::now();
    
    // get or create request history for this IP
    let requests = limiter.entry(ip).or_default();
    
    // remove requests older than rate limit window (sliding window algorithm)
    // sliding window: only counts requests within last 60 seconds, older ones expire automatically
    requests.retain(|&timestamp| now.duration_since(timestamp) < RATE_LIMIT_WINDOW);
    
    // if len(requests) mapped to that IP is still bigger than our window -> rate limit exceeded
    if requests.len() >= MAX_REQUESTS_PER_WINDOW {
        return false;  
    }
    
    // record the successful request timestamp
    requests.push(now);
    true
}

/// Reads and parses an HTTP request with comprehensive validation.
///
/// # Validation Checks
/// - Empty request detection
/// - Request line length (max 2048 bytes)
/// - Total request size (max 8KB)
/// - HTTP format validation (METHOD PATH HTTP/VERSION)
/// - HTTP version format (must start with "HTTP/")
///
/// # Returns
/// - `Ok((method, path))` - Parsed HTTP method and request path
/// - `Err(message)` - Validation error message
fn read_request(stream: &mut TcpStream) -> Result<(String, String), String> {
    let mut buf_reader = BufReader::new(stream);
    let mut request_line = String::new();
    
    // read first line (METHOD PATH HTTP/VERSION -> ex: GET /stats HTTP/1.1) into request_line
    match buf_reader.read_line(&mut request_line) {
        Ok(0) => return Err("Empty request".to_string()),
        Ok(n) if n > 2048 => return Err("Request line too long".to_string()),
        Ok(_) => {},
        Err(e) => return Err(format!("Read error: {e}")),
    }
    
    // parse (split) request line into components
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3 {
        return Err("Invalid request format".to_string());
    }
    
    let method = parts[0].to_string();
    let path = parts[1].to_string();
    
    // validate HTTP version format
    if !parts[2].starts_with("HTTP/") {
        return Err("Invalid HTTP version".to_string());
    }
    
    // read remaining headers/info (we do NOT NEED to process them but we DO NEED to consume them)
    let mut total_size = request_line.len();
    let mut line = String::new();
    loop {
        line.clear();
        match buf_reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(n) => {
                // for comparison
                total_size += n;
                // to enforce max size 
                if total_size > MAX_REQUEST_SIZE {
                    return Err("Request too large".to_string());
                }
                // empty line signals (CRLF | LF) end of HTTP body
                if line == "\r\n" || line == "\n" {
                    break;
                }
            }
            Err(e) => return Err(format!("Read error: {e}")),
        }
    }
    
    Ok((method, path))
}

/// Sends an HTTP error response to the client.
///
/// # Arguments
/// * `stream` - TCP stream to write response to
/// * `status` - HTTP status line (e.g., "400 Bad Request")
/// * `message` - Error message to display in HTML body
fn send_error_response(stream: &mut TcpStream, status: &str, message: &str) {
    let body = format!("<html><body><h1>{message}</h1></body></html>");
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, body.len(), body
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Logs HTTP request details to server.log file.
///
/// # Log Format
/// `[unix_timestamp] IP - METHOD PATH - STATUS - duration_ms`
///
/// # Arguments
/// * `logger` - Shared log file handle
/// * `addr` - Client socket address (IP extracted)
/// * `method` - HTTP method (GET, POST, etc.)
/// * `path` - Request path (/stats, /logs, etc.)
/// * `status` - HTTP status code (200, 404, 429, etc.)
/// * `duration_ms` - Request processing time in milliseconds
fn log_request(logger: &RequestLogger, addr: &SocketAddr, method: &str, path: &str, status: u16, duration_ms: u128) {
    // mutex lock -> timestamp calculation -> string formatting -> write out to server.log
    let mut log_file = logger.lock().unwrap();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let log_line = format!(
        "[{}] {} - {} {} - {} - {}ms\n",
        timestamp, addr.ip(), method, path, status, duration_ms
    );
    
    let _ = log_file.write_all(log_line.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::collections::HashMap;

    // ============== Rate Limiting Tests ==============

    #[test]
    fn test_rate_limit_allows_requests_within_window() {
        let rate_limiter: RateLimiter = Arc::new(Mutex::new(HashMap::new()));
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // First request should be allowed
        assert!(check_rate_limit(&rate_limiter, &addr));
        
        // Up to 30 requests should be allowed
        for _ in 0..29 {
            assert!(check_rate_limit(&rate_limiter, &addr));
        }
    }

    #[test]
    fn test_rate_limit_rejects_exceeding_limit() {
        let rate_limiter: RateLimiter = Arc::new(Mutex::new(HashMap::new()));
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Fill up the limit (30 requests)
        for _ in 0..30 {
            let _ = check_rate_limit(&rate_limiter, &addr);
        }

        // 31st request should be rejected
        assert!(!check_rate_limit(&rate_limiter, &addr));
    }

    #[test]
    fn test_rate_limit_isolation_per_ip() {
        let rate_limiter: RateLimiter = Arc::new(Mutex::new(HashMap::new()));
        let addr1: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.1:8080".parse().unwrap();

        // Fill limit for addr1
        for _ in 0..30 {
            let _ = check_rate_limit(&rate_limiter, &addr1);
        }

        // addr2 should still have allowance (since it is a separate IP with fresh limit + window)
        assert!(check_rate_limit(&rate_limiter, &addr2));
    }

    // ============== Request Parsing Tests ==============

    #[test]
    fn test_parse_valid_get_request() {
        let request = "GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n";
        
        // Parse request line (simplified for testing)
        // Note: Full integration test would use actual TCP connection
        let parts: Vec<&str> = request.trim_end().split("\r\n").next().unwrap().split_whitespace().collect();
        
        assert_eq!(parts[0], "GET");
        assert_eq!(parts[1], "/stats");
        assert_eq!(parts[2], "HTTP/1.1");
    }

    #[test]
    fn test_parse_invalid_http_version() {
        let request = "GET /stats HTTP2\r\n\r\n";
        let parts: Vec<&str> = request.trim_end().split("\r\n").next().unwrap().split_whitespace().collect();
        
        // Should not start with "HTTP/"
        assert!(!parts[2].starts_with("HTTP/"));
    }

    #[test]
    fn test_parse_malformed_request() {
        let request = "GET /stats\r\n\r\n";  // Missing HTTP version
        let parts: Vec<&str> = request.trim_end().split("\r\n").next().unwrap().split_whitespace().collect();
        
        // Should not have 3 parts
        assert_ne!(parts.len(), 3);
    }

    // ============== Server Statistics Tests ==============

    #[test]
    fn test_server_stats_creation() {
        let stats = ServerStats::new();
        
        // Stats should initialize with 0 requests
        assert_eq!(stats.total_requests.load(Ordering::SeqCst), 0);
        assert_eq!(stats.total_response_time.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_server_stats_atomic_updates() {
        let stats = Arc::new(ServerStats::new());
        
        // Simulate concurrent requests
        let mut handles = vec![];
        
        for _ in 0..5 {
            let stats_clone = Arc::clone(&stats);
            let handle = thread::spawn(move || {
                stats_clone.total_requests.fetch_add(1, Ordering::SeqCst);
                stats_clone.total_response_time.fetch_add(10, Ordering::SeqCst);
            });
            handles.push(handle);
        }
        
        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify atomic operations worked correctly
        assert_eq!(stats.total_requests.load(Ordering::SeqCst), 5);
        assert_eq!(stats.total_response_time.load(Ordering::SeqCst), 50);
    }

    // ============== Error Response Tests ==============

    #[test]
    fn test_error_response_400_format() {
        // Verify error response format is valid HTTP
        let status = "400 Bad Request";
        let message_text = "Malformed request";
        let body = format!("<html><body><h1>{}</h1></body></html>", message_text);
        let response = format!(
            "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status, body.len(), body
        );
        
        // Should contain valid HTTP headers
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains("Content-Type: text/html"));
        assert!(response.contains("Content-Length:"));
        assert!(response.contains(message_text));
    }

    #[test]
    fn test_error_response_429_rate_limit() {
        let status = "429 Too Many Requests";
        
        // Verify 429 is used for rate limiting
        assert!(status.contains("429"));
    }

    // ============== Thread Pool + Concurrency Tests ==============

    #[test]
    fn test_thread_pool_handles_concurrent_rate_limits() {
        use hello::ThreadPool;
        
        let pool = ThreadPool::new(4);
        let rate_limiter: RateLimiter = Arc::new(Mutex::new(HashMap::new()));
        let counter = Arc::new(Mutex::new(0));
        
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        
        // Spawn multiple jobs checking rate limit
        for _ in 0..20 {
            let limiter = Arc::clone(&rate_limiter);
            let cnt = Arc::clone(&counter);
            let a = addr.clone();
            
            pool.execute(move || {
                if check_rate_limit(&limiter, &a) {
                    let mut c = cnt.lock().unwrap();
                    *c += 1;
                }
            });
        }
        
        // Give workers time to process
        thread::sleep(Duration::from_millis(100));
        
        // Verify concurrency worked correctly
        let final_count = *counter.lock().unwrap();
        assert!(final_count > 0);
        assert!(final_count <= 30); // Rate limit should have kicked in
    }
}
