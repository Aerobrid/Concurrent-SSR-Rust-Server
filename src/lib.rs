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

// job is a closure that runs once + can be sent across threads
type Job = Box<dyn FnOnce() + Send + 'static>;

impl ThreadPool {
    // creates thread pool with fixed number of workers
    // panics if size is 0
    // fixed-size prevents thread exhaustion attacks
    pub fn new(size: usize) -> ThreadPool {
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

                match message {
                    Ok(job) => {
                        println!("Worker {} executing job", id);
                        job();
                        println!("Worker {} finished job", id);
                    }
                    Err(_) => {
                        // channel closed -> break out of loop and shutdown
                        println!("Worker {} disconnected; shutting down", id);
                        break;
                    }
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}