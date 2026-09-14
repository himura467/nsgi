# NSGI: Native Web Server Gateway Interface

A language-agnostic gateway interface protocol over C ABI. This crate provides the `#![no_std]`, zero-dependency Rust definitions of the NSGI protocol types and function signatures.

## Types

| Type | Role |
| ---- | ---- |
| `NsgiAddr` | A transport address in binary form |
| `NsgiHeader` | A single HTTP header name/value pair |
| `NsgiRequest` | HTTP request passed from host to application |
| `NsgiResponse` | HTTP response passed from application to host |
| `NsgiPending` | Cancellation registration the application writes when it defers the response |
| `NsgiOpenConnection` | Type alias for the `nsgi_open_connection` connection open signature |
| `NsgiApp` | Type alias for the `nsgi_handle` entry point signature |
| `NsgiFreeResponse` | Type alias for the `nsgi_free_response` cleanup signature |
| `NsgiCloseConnection` | Type alias for the `nsgi_close_connection` connection close signature |
| `NsgiGetVar` | Type alias for the host variable lookup carried on `NsgiRequest` |
| `NsgiReadRequestBody` | Type alias for the host request body read callback carried on `NsgiRequest` |
| `NsgiRespond` | Type alias for the host response completion callback carried on `NsgiRequest` |
| `NsgiReadResponseBody` | Type alias for the application response body read callback carried on `NsgiResponse` |
| `NsgiCancel` | Type alias for the application cancellation callback carried on `NsgiPending` |

## License

MIT
