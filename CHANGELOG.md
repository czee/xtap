# Changelog

## [0.2.0](https://github.com/czee/xtap/compare/0.1.0...0.2.0) - 2025-07-11

This release removes the `socket2` dependency and is mainly a refactor
of some modules:

- README shows tests use `nextest`
- Remove use of const 'static lifetime
- Use `LazyLock` for user defined IP/interface
- Remove `socket2` dependency
- Refactor `Bind::try_interface`
- Refactor `Hook` supertrait
- Refactor `net` functions
- Refactor `env` functions
- Prettify `bind` module
- Format with 2024 edition

## [0.1.0](https://github.com/czee/xtap) - 2025-07-02

Initial release

