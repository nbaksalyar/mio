use std::io::{Write, Read};

use mio::tcp::{TcpStream, TcpListener};
use mio::{Poll, Events, Ready, PollOpt, Token, Evented};

#[test]
fn write_then_drop() {
    drop(::env_logger::init());

    let a = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = a.local_addr().unwrap();
    let mut s = TcpStream::connect(&addr).unwrap();

    let poll = Poll::new().unwrap();

    a.register(&poll,
               Token(1),
               Ready::readable(),
               PollOpt::edge()).unwrap();
    s.register(&poll,
               Token(3),
               Ready::none(),
               PollOpt::edge()).unwrap();

    let mut events = Events::new();
    while events.len() == 0 {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.len(), 1);
    assert_eq!(events.get(0).unwrap().token(), Token(1));

    let mut s2 = a.accept().unwrap().0;

    s2.register(&poll,
                Token(2),
                Ready::writable(),
                PollOpt::edge()).unwrap();

    let mut events = Events::new();
    while events.len() == 0 {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.len(), 1);
    assert_eq!(events.get(0).unwrap().token(), Token(2));

    s2.write(&[1, 2, 3, 4]).unwrap();
    drop(s2);

    s.reregister(&poll,
                 Token(3),
                 Ready::readable(),
                 PollOpt::edge()).unwrap();
    let mut events = Events::new();
    while events.len() == 0 {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.len(), 1);
    assert_eq!(events.get(0).unwrap().token(), Token(3));

    let mut buf = [0; 10];
    assert_eq!(s.read(&mut buf).unwrap(), 4);
    assert_eq!(&buf[0..4], &[1, 2, 3, 4]);
}

#[test]
fn write_then_deregister() {
    drop(::env_logger::init());

    let a = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = a.local_addr().unwrap();
    let mut s = TcpStream::connect(&addr).unwrap();

    let poll = Poll::new().unwrap();

    a.register(&poll,
               Token(1),
               Ready::readable(),
               PollOpt::edge()).unwrap();
    s.register(&poll,
               Token(3),
               Ready::none(),
               PollOpt::edge()).unwrap();

    let mut events = Events::new();
    while events.len() == 0 {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.len(), 1);
    assert_eq!(events.get(0).unwrap().token(), Token(1));

    let mut s2 = a.accept().unwrap().0;

    s2.register(&poll,
                Token(2),
                Ready::writable(),
                PollOpt::edge()).unwrap();

    let mut events = Events::new();
    while events.len() == 0 {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.len(), 1);
    assert_eq!(events.get(0).unwrap().token(), Token(2));

    s2.write(&[1, 2, 3, 4]).unwrap();
    s2.deregister(&poll).unwrap();

    s.reregister(&poll,
                 Token(3),
                 Ready::readable(),
                 PollOpt::edge()).unwrap();
    let mut events = Events::new();
    while events.len() == 0 {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.len(), 1);
    assert_eq!(events.get(0).unwrap().token(), Token(3));

    let mut buf = [0; 10];
    assert_eq!(s.read(&mut buf).unwrap(), 4);
    assert_eq!(&buf[0..4], &[1, 2, 3, 4]);
}
