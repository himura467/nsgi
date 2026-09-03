//! # NSGI: Native Web Server Gateway Interface
//!
//! This crate provides the C ABI types and function pointer signature that form the NSGI protocol.
//! It is `#![no_std]` and has zero dependencies.
//!
//! NSGI is a language-agnostic gateway interface protocol that connects any C ABI host with
//! application logic written in any language supporting FFI.
//!
//! ## Field Validity
//!
//! Every field carrying HTTP message text is free of the bytes that delimit an HTTP/1.1 message:
//! no NUL, LF or CR at any position, and no leading or trailing SP or HTAB. A host rejects a
//! request carrying them, with 400 unless a more suitable status applies. An application does not
//! return them either, and a host answers 500 rather than transmitting them.
//!
//! ## Pointer Validity
//!
//! A pointer is non-null unless its own documentation says otherwise.
//!
//! ## Status Values
//!
//! A callback returns one of the statuses its own documentation names. Zero and positive values
//! report outcomes that are not failures; negative values report errors, and a negative value no
//! status list enumerates is reserved.
//!
//! ## Callback Safety
//!
//! Unwinding across a callback boundary is Undefined Behavior; an implementation catches its own
//! panics or builds with `panic = "abort"`. Calls for different requests may run concurrently on
//! any thread, so an implementation is reentrant and does not rely on unsynchronized mutable
//! state.
//!
//! ## Call Ordering
//!
//! Calls to one callback for the same request or response are never concurrent with each other,
//! whichever thread makes them, and are ordered so that state the application wrote during one
//! call is visible in the next.

#![no_std]

use core::ffi::c_void;

/// A scheme the host does not report.
pub const NSGI_SCHEME_UNKNOWN: u8 = 0;
/// A plaintext `http` hop the host terminated.
pub const NSGI_SCHEME_HTTP: u8 = 1;
/// A TLS `https` hop the host terminated.
pub const NSGI_SCHEME_HTTPS: u8 = 2;
/// A scheme the host terminated but cannot represent here. A host reporting this must supply
/// [`NsgiRequest::get_var`] and answer `request.scheme`.
pub const NSGI_SCHEME_OTHER: u8 = 3;

/// An address the host cannot represent here, though the connection exists.
pub const NSGI_AF_UNSPEC: u8 = 0;
/// An IPv4 address, carried in the first 4 bytes of [`NsgiAddr::octets`].
pub const NSGI_AF_INET: u8 = 1;
/// An IPv6 address, carried in all 16 bytes of [`NsgiAddr::octets`].
pub const NSGI_AF_INET6: u8 = 2;
/// A UNIX domain socket, named by [`NsgiAddr::path`].
pub const NSGI_AF_UNIX: u8 = 3;

/// A transport address in binary form.
///
/// # Ownership
/// Borrowed from the host. The application must not free these fields.
#[repr(C)]
pub struct NsgiAddr {
    /// One of the `NSGI_AF_*` constants.
    pub family: u8,
    /// Port in host byte order; 0 when not applicable. Note that `sockaddr_in::sin_port` is
    /// network byte order.
    pub port: u16,
    /// IPv6 zone index, as carried by `sockaddr_in6::sin6_scope_id`, meaningful only on the node
    /// that produced it. A host reports 0 for an address needing no zone.
    pub scope_id: u32,
    /// Address bytes in network byte order, IPv4 in the first 4; unused bytes are zero.
    /// The host must unmap IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) to [`NSGI_AF_INET`].
    pub octets: [u8; 16],
    /// UNIX socket path bytes. Null unless `family` is [`NSGI_AF_UNIX`];
    /// an unnamed socket has a `path_len` of 0.
    pub path: *const u8,
    pub path_len: usize,
}

/// A single HTTP header name/value pair.
///
/// # Header names
/// Names are lowercase in both directions: the host folds the names it delivers, and the
/// application supplies folded names. Folding maps bytes `0x41..=0x5A` to `0x61..=0x7A`
/// and leaves every other byte alone; values are unaffected. A host folds any uppercase
/// name it receives before transmitting.
///
/// Beyond case, a name carries no byte in `0x00..=0x20` or `0x7F..=0xFF`, and no colon.
///
/// # Ownership
/// Carried by [`NsgiRequest`], these fields are borrowed from the host and the application must
/// not free them. Carried by [`NsgiResponse`], they are the application's own; the host never
/// interprets or frees them, and static memory (e.g. `b"content-type"`) is as legal as heap.
#[repr(C)]
pub struct NsgiHeader {
    /// Header name bytes (e.g. `b"content-type"`).
    pub name: *const u8,
    pub name_len: usize,
    /// Header value bytes (e.g. `b"text/plain"`); an empty value has a `value_len` of 0.
    pub value: *const u8,
    pub value_len: usize,
}

/// The [`NsgiRequest::content_length`] of a request that declares no length, such as a chunked
/// request.
pub const NSGI_CONTENT_LENGTH_UNKNOWN: u64 = u64::MAX;

/// [`NsgiGetVar`] found the variable. A zero `*out_value_len` means a known but empty value.
pub const NSGI_VAR_OK: i32 = 0;
/// The host does not recognize the variable.
pub const NSGI_VAR_UNKNOWN: i32 = 1;
/// The lookup failed.
pub const NSGI_VAR_ERROR: i32 = -1;

/// The canonical type signature of the host's variable lookup callback.
///
/// Carries connection and server metadata such as `tls.version`, `tls.cipher`,
/// `server.software`, `proxy_protocol.src_addr`. Names are lowercase ASCII,
/// dot-separated, and compared bytewise. Request headers are not available here;
/// they are already in [`NsgiRequest::headers`].
///
/// `host_ctx` is [`NsgiRequest::host_ctx`] passed back unchanged. On [`NSGI_VAR_OK`] the host
/// writes a pointer and length borrowed for the duration of the `nsgi_handle` call, or, for a
/// call made after that return, until the next `get_var` call for the same request; on any
/// other return the out-params are left untouched.
///
/// Returns one of the `NSGI_VAR_*` statuses. A host that cannot report a value meeting the
/// [field validity rule](crate#field-validity) answers [`NSGI_VAR_ERROR`].
pub type NsgiGetVar = unsafe extern "C" fn(
    host_ctx: *mut c_void,
    name: *const u8,
    name_len: usize,
    out_value: *mut *const u8,
    out_value_len: *mut usize,
) -> i32;

/// A chunk is available. A zero-length chunk is not a legal success.
pub const NSGI_REQUEST_BODY_OK: i32 = 0;
/// The body is complete; no further bytes will follow.
pub const NSGI_REQUEST_BODY_END: i32 = 1;
/// No bytes are available at this moment, and more may follow; the application calls
/// `read_body` again. A synchronous host blocks instead of returning this.
pub const NSGI_REQUEST_BODY_AGAIN: i32 = 2;
/// The connection ended before the body was complete.
pub const NSGI_REQUEST_BODY_ERROR_TERMINATED: i32 = -1;
/// The body framing was invalid, such as a malformed chunked encoding.
pub const NSGI_REQUEST_BODY_ERROR_PROTOCOL: i32 = -2;
/// The body reached a limit the host enforces.
pub const NSGI_REQUEST_BODY_ERROR_TOO_LARGE: i32 = -3;
/// The host's read timeout fired before the next chunk arrived.
pub const NSGI_REQUEST_BODY_ERROR_TIMEOUT: i32 = -4;

/// The canonical type signature of the host's request body read callback.
///
/// Delivers the request body as chunks borrowed from host memory, one per call, in the order
/// the bytes arrived. `host_ctx` is [`NsgiRequest::host_ctx`] passed back unchanged. On
/// [`NSGI_REQUEST_BODY_OK`] the host writes the chunk pointer and length; on any other status the
/// out-params are left untouched.
///
/// Returns one of the `NSGI_REQUEST_BODY_*` statuses.
///
/// # Chunk lifetime
/// A chunk stays valid until the next call for the same request, and, for a call made during
/// `nsgi_handle`, never beyond that return. The application copies whatever it keeps past that
/// point, such as a fragment spanning a chunk boundary. A call moves past the end of the current
/// chunk rather than reading a requested number of bytes.
///
/// # Terminal statuses
/// Once [`NSGI_REQUEST_BODY_END`] or an error is reported, every later call reports that same
/// status. A request carrying no body reports [`NSGI_REQUEST_BODY_END`] on the first call.
///
/// # Host obligations
/// The host answers `Expect: 100-continue` on the first call and not before it. An application
/// may respond with the body unread; the host then drains the remainder or closes the
/// connection rather than parsing those bytes as a subsequent message.
pub type NsgiReadRequestBody = unsafe extern "C" fn(
    host_ctx: *mut c_void,
    out_chunk: *mut *const u8,
    out_chunk_len: *mut usize,
) -> i32;

/// The canonical type signature of the host's response completion callback.
///
/// Carries the response for a request whose `nsgi_handle` call returned [`NSGI_HANDLE_PENDING`].
/// `host_ctx` is [`NsgiRequest::host_ctx`] passed back unchanged. The application calls it exactly
/// once for every such request, and never for one it answered through the out-parameter.
///
/// # Lifetimes
/// The pointer addresses storage the application owns, borrowed for the duration of the call;
/// the host copies whatever it keeps.
///
/// # Ordering
/// The call may come from any thread, including one the host did not create, and may precede
/// `nsgi_handle` returning [`NSGI_HANDLE_PENDING`], which the host waits for before treating
/// the response as available. It must not come from within `nsgi_handle` on the thread running
/// it, where the application answers through the out-parameter instead, nor from within
/// [`NsgiCancel`].
///
/// An application that both made this call and returned [`NSGI_HANDLE_DONE`] produces two
/// responses: the host transmits the one in the out-parameter and passes the other to
/// `nsgi_free_response` without transmitting it.
///
/// The host orders the call so that state the application wrote before making it is visible to
/// the thread that afterwards reads the response and calls [`NsgiResponse::read_body`].
pub type NsgiRespond = unsafe extern "C" fn(host_ctx: *mut c_void, res: *const NsgiResponse);

/// An HTTP request constructed by the host and passed to the application.
///
/// # Ownership
/// Every pointer field is borrowed from the host for the duration of the `nsgi_handle` call. The
/// application must not free any of them. Body chunks are borrowed on the narrower window
/// described on [`NsgiReadRequestBody`].
#[repr(C)]
pub struct NsgiRequest {
    /// One of the `NSGI_SCHEME_*` constants. Describes the hop the host itself terminated;
    /// never derived from `X-Forwarded-Proto`.
    pub scheme: u8,
    /// HTTP major version, 0 when the version is unknown.
    pub http_version_major: u8,
    /// HTTP minor version, 0 when the version is unknown or has no minor part.
    pub http_version_minor: u8,
    /// The transport peer that opened the connection. Null when the host has no peer.
    /// Never derived from `X-Forwarded-For` or `Forwarded`.
    pub peer: *const NsgiAddr,
    /// The local address the connection was accepted on. Null when the host has none.
    pub local: *const NsgiAddr,
    /// HTTP method bytes (e.g. `b"GET"`).
    pub method: *const u8,
    pub method_len: usize,
    /// Authority component bytes, as received and including any port. Taken from the request
    /// target when it is in absolute form, otherwise from `:authority` or `Host`. Never
    /// carries the deprecated userinfo subcomponent; a host rejects such a request.
    /// Null when the request conveys no authority.
    pub authority: *const u8,
    pub authority_len: usize,
    /// Path component bytes as received (e.g. `b"/api/v1"`); a host does not percent-decode.
    pub path: *const u8,
    pub path_len: usize,
    /// Query component bytes as received; a host does not percent-decode. The `?` delimiter is
    /// excluded. Null when `query_len` is 0.
    pub query: *const u8,
    pub query_len: usize,
    /// Request headers, carrying no `host` (reported through `authority`), no `content-length`
    /// (through `content_length`), no `transfer-encoding` (already decoded), and no
    /// pseudo-header. Null when `headers_len` is 0.
    pub headers: *const NsgiHeader,
    pub headers_len: usize,
    /// The body length the request declared, or [`NSGI_CONTENT_LENGTH_UNKNOWN`] when it declared
    /// none; a host rejects a request declaring that length. A client may declare a length and
    /// stop sending short of it. A host accepting a request that declares both a length and a
    /// transfer coding honors the coding alone, reports the length unknown, and closes the
    /// connection after responding.
    pub content_length: u64,
    /// Opaque host context pointer, possibly null. The application must not dereference or free
    /// this.
    pub host_ctx: *mut c_void,
    /// Host variable lookup, receiving `host_ctx` unchanged. `None` when the host supplies
    /// no variables.
    pub get_var: Option<NsgiGetVar>,
    /// Request body delivery, receiving `host_ctx` unchanged. The host supplies it for every
    /// request, including one that carries no body.
    pub read_body: NsgiReadRequestBody,
    /// Response completion, receiving `host_ctx` unchanged. The host supplies it for every
    /// request.
    pub respond: NsgiRespond,
}

/// A chunk is available. A zero-length chunk is not a legal success.
pub const NSGI_RESPONSE_BODY_OK: i32 = 0;
/// The body is complete; no further bytes will follow.
pub const NSGI_RESPONSE_BODY_END: i32 = 1;
/// No bytes are available at this moment, and more may follow; the host calls `read_body`
/// again. A synchronous application blocks instead of returning this.
pub const NSGI_RESPONSE_BODY_AGAIN: i32 = 2;
/// The application failed and the body will not complete. The status line is already committed,
/// so the host leaves the message incomplete rather than completing it: it sends no terminating
/// chunk, does not pad to a declared length, and closes the connection or resets the stream.
pub const NSGI_RESPONSE_BODY_ERROR: i32 = -1;

/// The canonical type signature of the application's response body read callback.
///
/// Delivers the response body as chunks borrowed from application memory, one per call.
/// `app_ctx` is [`NsgiResponse::app_ctx`] passed back unchanged. On [`NSGI_RESPONSE_BODY_OK`] the
/// application writes the chunk pointer and length; on any other status the out-params are left
/// untouched.
///
/// Returns one of the `NSGI_RESPONSE_BODY_*` statuses.
///
/// # Chunk lifetime
/// A chunk stays valid until the next call for the same response, and never beyond
/// `nsgi_free_response`. A host that transmitted part of a chunk keeps the remainder by not
/// calling again; one coalescing several chunks into a single write copies them.
///
/// The callback runs after `nsgi_handle` has returned, so a chunk must not point into the
/// request, into a value obtained from `get_var`, or into a chunk obtained from
/// [`NsgiRequest::read_body`].
///
/// # Terminal statuses
/// Once [`NSGI_RESPONSE_BODY_END`] or [`NSGI_RESPONSE_BODY_ERROR`] is reported, every later call
/// reports that same status. A response carrying no body reports [`NSGI_RESPONSE_BODY_END`] on
/// the first call.
///
/// # Ordering
/// A call may come from a thread other than the one that ran `nsgi_handle`.
///
/// # Host obligations
/// A host unable to accept more bytes at this moment stops calling until it can, which is the
/// whole of backpressure. It may instead stop permanently and go straight to
/// `nsgi_free_response`, which is what a client disconnecting, a host timeout, or a connection
/// error looks like from the application's side; abandonment carries no status. A callback that
/// neither yields nor completes is bounded by the host's idle timeout.
///
/// The host may transmit the status line and header section as soon as the response reaches it.
pub type NsgiReadResponseBody = unsafe extern "C" fn(
    app_ctx: *mut c_void,
    out_chunk: *mut *const u8,
    out_chunk_len: *mut usize,
) -> i32;

/// An HTTP response constructed by the application and passed to the host.
///
/// # Ownership
/// The application owns all memory reachable through it, and the host borrows it until the
/// [`NsgiFreeResponse`] call that releases it. The host must not modify or free any field
/// directly. Body chunks are borrowed on the narrower window described on
/// [`NsgiReadResponseBody`].
#[repr(C)]
pub struct NsgiResponse {
    /// HTTP status code (e.g. `200`, `404`).
    pub status: u16,
    /// Response headers, carrying `content-length` when the application knows the body's length
    /// and never `transfer-encoding`. Null when `headers_len` is 0.
    ///
    /// A transfer coding frames the connection the host terminated, and chunk boundaries are not
    /// message framing. A host transmits a declared length as given and holds the application to
    /// it, treating a body that ends short of or runs past it as [`NSGI_RESPONSE_BODY_ERROR`];
    /// absent a declared length it frames the response with whatever its protocol version
    /// provides.
    pub headers: *const NsgiHeader,
    pub headers_len: usize,
    /// Opaque application context pointer, possibly null. The host must not dereference or free
    /// this.
    pub app_ctx: *mut c_void,
    /// Response body delivery, receiving `app_ctx` unchanged. The application supplies it for
    /// every response, including one that carries no body.
    pub read_body: NsgiReadResponseBody,
}

/// Status values returned by `NsgiApp`. Zero and positive values report outcomes that are not
/// failures; negative values are reserved. No failure status is defined: an application that
/// cannot produce a response answers with one.
///
/// The response is in the response out-parameter and the request is complete.
pub const NSGI_HANDLE_DONE: i32 = 0;
/// The application supplies the response later through `NsgiRequest::respond`, and left the
/// response out-parameter untouched.
pub const NSGI_HANDLE_PENDING: i32 = 1;

/// The canonical type signature of the application's cancellation callback.
///
/// The host calls it once it has stopped wanting the response, such as when the client
/// disconnected, its own timeout fired, or the connection failed. `cancel_ctx` is
/// `NsgiPending::cancel_ctx` passed back unchanged.
///
/// It does not release the application from calling `NsgiRequest::respond`: the application
/// makes that call in every case, and the host discards the response to a request it has
/// abandoned. Nothing reaches `cancel_ctx` once `respond` has returned, so that is where the
/// application releases it.
///
/// # Ordering
/// The call happens at most once and never before `nsgi_handle` has returned
/// `NSGI_HANDLE_PENDING`; a host that detected the condition earlier makes it once that return
/// has happened. It never runs concurrently with the request's `respond` call and never follows
/// one, so a `respond` call may be waiting on it: it must not wait on anything that path holds,
/// and must not itself call `respond`. The host orders it so that state the host wrote
/// beforehand is visible within it. Against the application's own work on the request it is not
/// ordered at all, the condition it reports arriving independently of that work, and the
/// request's handles keep their meanings afterwards and report their own errors.
///
/// # Host obligations
/// A host may reclaim a canceled request once this call has returned, after which a `respond`
/// call naming that request, or any other call naming it, is discarded rather than undefined.
/// Reclaiming requires that no value the host has presented as `host_ctx` name a different
/// request while the application may still hold it.
pub type NsgiCancel = unsafe extern "C" fn(cancel_ctx: *mut c_void);

/// The application's registration for cancellation notice, written on `NSGI_HANDLE_PENDING`.
///
/// The host initializes it to no cancellation before calling `nsgi_handle`, so an application
/// wanting none leaves it untouched. It is the only out-parameter the host writes before the
/// call.
#[repr(C)]
pub struct NsgiPending {
    /// Opaque application context, passed back to `cancel` unchanged. The host must not
    /// dereference or free this.
    pub cancel_ctx: *mut c_void,
    /// Cancellation notice. `None` when the application wants none.
    pub cancel: Option<NsgiCancel>,
}

/// The canonical type signature of an NSGI application entry point.
///
/// Every NSGI application must provide a C ABI function with this signature:
///
/// ```rust,ignore
/// #[no_mangle]
/// pub unsafe extern "C" fn nsgi_handle(
///     req: *const NsgiRequest,
///     out_res: *mut NsgiResponse,
///     out_pending: *mut NsgiPending,
/// ) -> i32 { ... }
/// ```
///
/// Returns one of the `NSGI_HANDLE_*` statuses. Neither out-parameter is null, and each is
/// written only on the status that names it.
///
/// # Execution Constraints
///
/// - **Lifetimes**: `req` is never null and addresses storage the host owns; the application must
///   not free it, and must not hold references to it or any of its fields after returning,
///   whichever status it returns. `host_ctx` and the callbacks beside it are values rather than
///   borrowed memory, so an application that copied them out goes on calling them afterwards.
/// - **Thread Safety**: The host may invoke this entry point concurrently from multiple OS threads.
///   The implementation must be reentrant and must not rely on unsynchronized mutable state.
/// - **No Panics**: Unwinding into the host is Undefined Behavior.
///   Catch panics internally or use `panic = "abort"`.
pub type NsgiApp = unsafe extern "C" fn(
    req: *const NsgiRequest,
    out_res: *mut NsgiResponse,
    out_pending: *mut NsgiPending,
) -> i32;

/// The canonical type signature of the NSGI response cleanup function.
///
/// Every NSGI application must provide a C ABI function with this signature:
///
/// ```rust,ignore
/// #[no_mangle]
/// pub unsafe extern "C" fn nsgi_free_response(res: *const NsgiResponse) { ... }
/// ```
///
/// The host **must** call this exactly once for every response the application handed over,
/// through either path and including one carried by a `NsgiRequest::respond` call the host
/// discarded, so the application can release whatever it allocated. The call comes after the
/// last `NsgiResponse::read_body` call and never concurrently with one, whether or not the
/// body reached completion.
///
/// The pointer is never null and addresses storage the host owns, borrowed for the duration of
/// the call: the application releases what the fields point to, not the storage the pointer
/// addresses, and does not retain the pointer past the return.
pub type NsgiFreeResponse = unsafe extern "C" fn(*const NsgiResponse);
