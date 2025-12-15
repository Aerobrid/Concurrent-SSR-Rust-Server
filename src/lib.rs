use std::{
    sync::{Arc, Mutex, mpsc},
    thread,
};

// thread pool for executing jobs with fixed worker count
// instead of spawning thread per request, queue the jobs
pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<mpsc::Sender<Job>>,
}

// job is a closure that runs once + can be sent across threads + not sure how long the thread (worker) will take to execute job
type Job = Box<dyn FnOnce() + Send + 'static>;

impl ThreadPool {
    // creates thread pool with fixed number of workers
    // fixed-size prevents thread exhaustion attacks
    #[must_use]
    pub fn new(size: usize) -> ThreadPool {
        // panics if size is 0
        assert!(size > 0, "Thread pool size must be greater than 0");

        // Multiple Producer Single Consumer -> create a channel for sending jobs (connections) to workers
        let (sender, receiver) = mpsc::channel();

        // Arc<Mutex<>> allows multiple workers to safely share receiver
        // Arc => thread-safe reference counting
        // Mutex => only one thread accesses at a time
        let receiver = Arc::new(Mutex::new(receiver));

        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }

        ThreadPool {
            workers,
            sender: Some(sender),
        }
    }

    // executes job in the thread pool
    // job will be picked up by an available worker
    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        // box closure on heap (size unknown at compile time)
        let job = Box::new(f);

        // send job through channel to workers
        self.sender.as_ref().unwrap().send(job).unwrap();
    }
}

impl Drop for ThreadPool {
    // graceful shutdown when pool is dropped
    // 1. close sender to signal no more jobs
    // 2. wait for all workers to finish current jobs
    fn drop(&mut self) {
        // drop sender closes the channel
        drop(self.sender.take());

        for worker in &mut self.workers {
            println!("Shutting down worker {}", worker.id);

            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

// worker thread that processes jobs from shared queue
// multiple workers compete for jobs efficiently
struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    // creates new worker thread
    // worker loops forever receiving and executing jobs
    // exits when channel closes
    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Job>>>) -> Worker {
        let thread = thread::spawn(move || {
            loop {
                // lock mutex to access receiver (one worker at a time)
                // recv() releases lock while waiting
                let message = receiver.lock().unwrap().recv();

                if let Ok(job) = message {
                    println!("Worker {id} executing job");
                    job();
                    println!("Worker {id} finished job");
                } else {
                    // channel closed -> break out of loop and shutdown
                    println!("Worker {id} disconnected; shutting down");
                    break;
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Verifies that ThreadPool::new creates the correct number of worker threads.
    #[test]
    fn test_threadpool_new_creates_workers() {
        let pool = ThreadPool::new(4);
        assert_eq!(pool.workers.len(), 4);
    }

    /// Ensures ThreadPool panics with size 0 to prevent invalid pool creation.
    #[test]
    #[should_panic(expected = "Thread pool size must be greater than 0")]
    fn test_threadpool_new_panics_on_zero() {
        let _ = ThreadPool::new(0);
    }

    /// Tests that a single job executes and increments the counter atomically.
    #[test]
    fn test_threadpool_execute_runs_job() {
        let pool = ThreadPool::new(2);
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        pool.execute(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });

        thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    /// Validates that multiple jobs execute in sequence without losing count.
    #[test]
    fn test_threadpool_execute_multiple_jobs() {
        let pool = ThreadPool::new(2);
        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..5 {
            let c = Arc::clone(&counter);
            pool.execute(move || {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }

        thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    /// Tests concurrent execution: 4 workers handle 10 jobs correctly under load.
    #[test]
    fn test_threadpool_concurrent_execution() {
        let pool = ThreadPool::new(4);
        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..10 {
            let c = Arc::clone(&counter);
            pool.execute(move || {
                thread::sleep(std::time::Duration::from_millis(10));
                c.fetch_add(1, Ordering::SeqCst);
            });
        }

        thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }
}
