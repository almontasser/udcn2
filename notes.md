Fixed Commands for Running μDCN Benchmarks

  1. Start the Test Server (Terminal 1)

  cd /root/udcn2
  RUST_LOG=info ./target/release/test-server --bind 127.0.0.1:4433

  2. Run Basic Interest Test (Terminal 2)

  cd /root/udcn2
  RUST_LOG=info ./target/release/udcn2-cli interest --server 127.0.0.1:4433 --name "/test/data" --count 5 --interval 1000

  3. Run Performance Benchmark (Terminal 2)

  cd /root/udcn2
  RUST_LOG=info ./target/release/udcn2-cli benchmark --server 127.0.0.1:4433 --connections 10 --duration 15

  4. Run XDP Monitor (Terminal 3)

  cd /root/udcn2
  RUST_LOG=info ./target/release/udcn2-xdp --iface eth0 --stats-interval 5 --verbose

  What the Fix Included:

  1. Updated QuicTransport to use insecure client configuration (skips certificate verification for testing)
  2. Added crypto provider initialization to both CLI and test server
  3. Created a test server binary that the CLI can actually connect to
  4. Fixed the "no default client config" error by properly configuring the QUIC client

  Expected Output:

  Test Server:
  INFO Starting μDCN test server on 127.0.0.1:4433
  INFO μDCN test server listening on 127.0.0.1:4433
  INFO Received Interest: /test/data/0
  INFO Received Interest: /test/data/1

  CLI Client:
  INFO Starting Interest test: 5 requests to 127.0.0.1:4433
  INFO Request 0: Got data '/test/data/0' in 12.5ms
  INFO Request 1: Got data '/test/data/1' in 8.3ms

  The configuration error should now be resolved and you'll be able to run proper end-to-end benchmarks!


-----


Here are the commands to run the μDCN benchmarks and tools:

  1. Build the Project

  cd /root/udcn2
  cargo build --release

  2. Run CLI Benchmarks

  Basic Interest Test

  # Send 10 Interest packets to a server
  ./target/release/udcn2-cli interest --server 127.0.0.1:4433 --name "/test/data" --count 10 --interval 500

  Performance Benchmark

  # Run benchmark with 20 concurrent connections for 30 seconds
  ./target/release/udcn2-cli benchmark --server 127.0.0.1:4433 --connections 20 --duration 30

  High-Load Benchmark

  # Stress test with 100 concurrent connections
  ./target/release/udcn2-cli benchmark --server 127.0.0.1:4433 --connections 100 --duration 60

  3. Run XDP Performance Monitor

  # Start XDP loader with statistics (mock mode)
  sudo ./target/release/udcn2-xdp --iface eth0 --stats-interval 5 --verbose

  4. Run Integration Tests

  # Run all integration tests
  cargo test --package integration_test

  # Run specific test
  cargo test --package integration_test test_client_creation

  5. Example Full Workflow

  Terminal 1 - Start a Mock Server (for testing)

  # The CLI will attempt to connect to servers, but for demo purposes you can see the connection attempts
  RUST_LOG=info ./target/release/udcn2-cli interest --count 5 --interval 1000

  Terminal 2 - Monitor XDP Performance

  # Monitor packet processing statistics
  sudo RUST_LOG=info ./target/release/udcn2-xdp --verbose --stats-interval 3

  Terminal 3 - Run Benchmark

  # Run concurrent benchmark test
  RUST_LOG=info ./target/release/udcn2-cli benchmark --connections 10 --duration 15

  6. Available CLI Options

  Interest Command

  - --server: Target server address (default: 127.0.0.1:4433)
  - --name: NDN name to request (default: /example/data)
  - --count: Number of requests (default: 1)
  - --interval: Interval between requests in ms (default: 1000)

  Benchmark Command

  - --server: Target server address (default: 127.0.0.1:4433)
  - --connections: Number of concurrent connections (default: 10)
  - --duration: Duration in seconds (default: 30)

  XDP Loader Options

  - --iface: Network interface (default: eth0)
  - --stats-interval: Statistics reporting interval in seconds (default: 5)
  - --verbose: Enable detailed statistics

  7. Expected Output

  The benchmarks will show:
  - Request latency for individual Interest/Data exchanges
  - Success rate percentage
  - Requests per second throughput
  - Connection statistics for concurrent tests
  - XDP packet processing stats (in mock mode)

  Note: Since this is a development environment, the tools will primarily demonstrate the architecture and performance monitoring capabilities. For full eBPF functionality, you'd need to deploy on a system with
  nightly Rust toolchain and appropriate network interfaces.
