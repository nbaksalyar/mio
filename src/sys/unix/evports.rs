use std::{cmp, fmt, ptr};
use std::os::raw::c_uint;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::time::Duration;

use libc::{self, time_t};

use {io, Ready, PollOpt, Token};
use event_imp::{self as event, Event};
use sys::unix::{cvt, UnixReady};
use sys::unix::io::set_cloexec;

/// Each Selector has a globally unique(ish) ID associated with it. This ID
/// gets tracked by `TcpStream`, `TcpListener`, etc... when they are first
/// registered with the `Selector`. If a type that is previously associated with
/// a `Selector` attempts to register itself with a different `Selector`, the
/// operation will return with an error. This matches windows behavior.
static NEXT_ID: AtomicUsize = ATOMIC_USIZE_INIT;

pub struct Selector {
    id: usize,
    port: RawFd,
}

impl Selector {
    pub fn new() -> io::Result<Selector> {
        // offset by 1 to avoid choosing 0 as the id of a selector
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed) + 1;
        let port = unsafe { try!(cvt(libc::port_create())) };
        drop(set_cloexec(port));

        Ok(Selector {
            id: id,
            port: port,
        })
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn select(&self, evts: &mut Events, awakener: Token, timeout: Option<Duration>) -> io::Result<bool> {
        let timeout = timeout.map(|to| {
            libc::timespec {
                tv_sec: cmp::min(to.as_secs(), time_t::max_value() as u64) as time_t,
                tv_nsec: to.subsec_nanos() as libc::c_long,
            }
        });
        let timeout = timeout.as_ref().map(|s| s as *const _).unwrap_or(ptr::null_mut());

        unsafe {
            let mut nevents = 1;
            try!(cvt(libc::port_getn(self.port,
                                     evts.sys_events.0.as_mut_ptr(),
                                     evts.sys_events.0.capacity() as c_uint,
                                     &mut nevents,
                                     timeout)));
            evts.sys_events.0.set_len(nevents as usize);
            Ok(evts.coalesce(awakener))
        }
    }

    pub fn register(&self, fd: RawFd, token: Token, interests: Ready, _opts: PollOpt) -> io::Result<()> {
        trace!("registering; token={:?}; interests={:?}", token, interests);

        // let flags = if opts.contains(PollOpt::edge()) { libc::EV_CLEAR } else { 0 } |
        //            if opts.contains(PollOpt::oneshot()) { libc::EV_ONESHOT } else { 0 } |
        //            libc::EV_RECEIPT;

        unsafe {
            let mut events: i32 = 0;
            if interests.contains(Ready::readable()) {
                events |= libc::POLLIN as i32;
            }
            if interests.contains(Ready::writable()) {
                events |= libc::POLLOUT as i32;
            }
            try!(cvt(libc::port_associate(self.port, libc::PORT_SOURCE_FD, fd as usize, events, usize::from(token))));
            Ok(())
        }
    }

    pub fn reregister(&self, fd: RawFd, token: Token, interests: Ready, opts: PollOpt) -> io::Result<()> {
        // Just need to call register here since EV_ADD is a mod if already
        // registered
        self.register(fd, token, interests, opts)
    }

    pub fn deregister(&self, fd: RawFd) -> io::Result<()> {
        unsafe {
            try!(cvt(libc::port_dissociate(self.port, libc::PORT_SOURCE_FD, fd as usize)));
            Ok(())
        }
    }
}

impl fmt::Debug for Selector {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Selector")
            .field("id", &self.id)
            .field("port", &self.port)
            .finish()
    }
}

impl AsRawFd for Selector {
    fn as_raw_fd(&self) -> RawFd {
        self.port
    }
}

impl Drop for Selector {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.port);
        }
    }
}

pub struct Events {
    sys_events: PortEventList,
    events: Vec<Event>,
    event_map: HashMap<Token, usize>,
}

struct PortEventList(Vec<libc::port_event>);

unsafe impl Send for PortEventList {}
unsafe impl Sync for PortEventList {}

impl Events {
    pub fn with_capacity(cap: usize) -> Events {
        Events {
            sys_events: PortEventList(Vec::with_capacity(cap)),
            events: Vec::with_capacity(cap),
            event_map: HashMap::with_capacity(cap)
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.events.capacity()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn get(&self, idx: usize) -> Option<Event> {
        self.events.get(idx).map(|e| *e)
    }

    fn coalesce(&mut self, awakener: Token) -> bool {
        let mut ret = false;
        self.events.clear();
        self.event_map.clear();

        for e in self.sys_events.0.iter() {
            let token = Token(e.portev_user as usize);
            let len = self.events.len();

            if token == awakener {
                // TODO: Should this return an error if event is an error. It
                // is not critical as spurious wakeups are permitted.
                ret = true;
                continue;
            }

            let idx = *self.event_map.entry(token)
                .or_insert(len);

            if idx == len {
                // New entry, insert the default
                self.events.push(Event::new(Ready::empty(), token));
            }

            if e.portev_events & libc::POLLERR as i32 != 0 {
                event::kind_mut(&mut self.events[idx]).insert(*UnixReady::error());
            }
            if e.portev_events & libc::POLLIN as i32 != 0 {
                event::kind_mut(&mut self.events[idx]).insert(Ready::readable());
            }
            if e.portev_events & libc::POLLOUT as i32 != 0 {
                event::kind_mut(&mut self.events[idx]).insert(Ready::writable());
            }
            if e.portev_events & libc::POLLHUP as i32 != 0 {
                event::kind_mut(&mut self.events[idx]).insert(UnixReady::hup());
            }
        }

        ret
    }

    pub fn push_event(&mut self, event: Event) {
        self.events.push(event);
    }
}

impl fmt::Debug for Events {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Events {{ len: {} }}", self.sys_events.0.len())
    }
}
