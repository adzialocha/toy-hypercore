# toy-hypercore

A toy [Hypercore](https://github.com/datproject/docs/blob/master/papers/dat-paper.pdf) p2p protocol implementation with local [mDNS discovery](https://en.wikipedia.org/wiki/Multicast_DNS) for learning purposes.

Please note: *This is work in progress and will be published together with a tutorial when finished.*

## Usage

Start sharing Hypercore feed:

  ```
  cargo run
  > dat://20d7eb0934d482fca4f975270b8ad6e28ecbdeebad5bed8c1acd5006eec771ea
  ```

Clone Hypercore feed with address:

  ```
  cargo run -- -c dat://20d7eb0934d482fca4f975270b8ad6e28ecbdeebad5bed8c1acd5006eec771ea
  ```
