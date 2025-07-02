# xtap

`xtap` is a Rust crate used with `LD_PRELOAD` to hook `bind()` and `connect()` syscalls to reroute v4 and v6 addresses with environment variables.

## Features

- Intercepts `bind()` and `connect()` syscalls using runtime hooking via `dlsym`
- Automatically binds sockets to an interface
- Supports IPv4 and IPv6
- Configurable via multiple environment variables
- Minimal runtime overhead

## Environment Variables

`xtap` should only be given one environment variable. If more are given the interface will take precedence over IP and be ignored. When an IP is specified it will use the corresponding interface.

| Variable         | Example          |
|------------------|------------------|
| `XTAP_IFACE`     | `eth0`           |
| `XTAP_INTERFACE` | `tun0`           |
| `XTAP_IP`        | `192.168.1.100`  |
| `BIND_IP`        | `10.0.0.2`       |
| `BIND_SRC`       | `10.0.0.3`       |
| `XTAP_ADDR`      | `172.16.0.1`     |
| `XTAP_BIND`      | `192.168.2.1`    |
| `XTAP_BIND_ADDR` | `192.168.3.1`    |

## Building

    cargo build --release

## Usage

1. Set environment variables to specify interface or IP:

   ```
   export XTAP_IFACE=eth0
   export XTAP_IP=192.168.1.100
   ```

2. Run your binary using `LD_PRELOAD`. Socket operations will be transparently bound as configured. `connect()` calls will automatically inject a `bind()` and `setsockopt()` call.
    ```
    LD_PRELOAD=/usr/lib/xtap/libxtap.so \
    XTAP_IFACE=tun0 \
    curl -4 -L "http://cloudflare.com/cdn-cgi/trace"
    ```

3. If integrating the `xtap` crate, ensure your binary uses the provided `bind()` and `connect()` hooks:

    ```
   pub fn bind(sockfd: i32, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
       xtap::hooks::Bind::bind(sockfd, addr, addrlen)
   }

   pub fn connect(sockfd: i32, addr: *const sockaddr, addrlen socklen_t) -> i32 {
       xtap::hooks::Connect::connect(sockfd, addr, addrlen)
   }
    ```

## Debugging

Enable debug logging by compiling with debug assertions:

`cargo build --debug`

## Testing

Run tests single-threaded to avoid environment variable race conditions:

`cargo test -- --test-threads=1`

## Dependencies
- [`libc`](https://crates.io/crates/libc) and [`socket2`](https://crates.io/crates/socket2) for socket handling and syscall hooking
- [`netdev`](https://crates.io/crates/netdev) to discover network interfaces
- [`scopeguard`](https://crates.io/crates/scopeguard) for scoped cleanup and guard patterns

## License

This project is available under multiple licenses. You may choose to use it under one of the following:

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-Apache)
- [Apache License 2.0 with LLVM Exception](LICENSE-Apache-2.0_WITH_LLVM-exception)

## Prior Art

Inspired by [`bindhack`](http://wari.mckay.com/~rm/bindhack.c.txt)

## Contribution

Contributions are welcome! Open issues or PRs on the repository.
