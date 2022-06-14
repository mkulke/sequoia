use std::io;
use std::fmt;

use crate::BufferedReader;

/// References a `BufferedReader`.
///
/// This is a non-owning mutable reference type for the buffered
/// reader framework.  It can be used to retain ownership of the
/// reader when using interfaces that consume the reader.
#[derive(Debug)]
pub struct Mut<'a, T, C>
where
    T: BufferedReader<C> + ?Sized,
    C: fmt::Debug + Send + Sync,
{
    reader: &'a mut T,
    _ghostly_cookie: std::marker::PhantomData<C>,
}

// There is a bug in assert_send_and_sync that prevents us from
// declaring multiple trait bounds on C.  As a quick workaround, we
// define a local alias that combines Default and Debug for the sole
// benefit of the assert_send_and_sync macro.
mod appease_macro {
    pub(crate) trait DefaultDebug: Default + std::fmt::Debug {}

    assert_send_and_sync!(super::Mut<'_, T, C>
                          where T: crate::BufferedReader<C>,
                                C: DefaultDebug);
}

impl<'a, T, C> fmt::Display for Mut<'a, T, C>
where
    T: BufferedReader<C> + ?Sized,
    C: fmt::Debug + Send + Sync,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Mut")
            .finish()
    }
}

impl<'a, T, C> Mut<'a, T, C>
where
    T: BufferedReader<C> + ?Sized,
    C: fmt::Debug + Send + Sync,
{
    /// Makes a new mutable reference.
    ///
    /// `reader` is the source to reference.
    pub fn new(reader: &'a mut T) -> Self {
        Mut {
            reader,
            _ghostly_cookie: Default::default(),
        }
    }
}

impl<'a, T, C> io::Read for Mut<'a, T, C>
where
    T: BufferedReader<C> + ?Sized,
    C: fmt::Debug + Send + Sync,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.reader.read(buf)
    }
}

impl<'a, T, C> BufferedReader<C> for Mut<'a, T, C>
where
    T: BufferedReader<C> + ?Sized,
    C: fmt::Debug + Send + Sync,
{
    fn buffer(&self) -> &[u8] {
        self.reader.buffer()
    }

    fn data(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        self.reader.data(amount)
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        self.reader.consume(amount)
    }

    fn get_mut(&mut self) -> Option<&mut dyn BufferedReader<C>> {
        self.reader.get_mut()
    }

    fn get_ref(&self) -> Option<&dyn BufferedReader<C>> {
        self.reader.get_ref()
    }

    fn as_boxed<'b>(self) -> Box<dyn BufferedReader<C> + 'b>
        where Self: 'b
    {
        Box::new(self)
    }

    /// This will always return `None`.
    fn into_inner<'b>(self: Box<Self>) -> Option<Box<dyn BufferedReader<C> + 'b>>
            where Self: 'b {
        None
    }

    fn cookie_set(&mut self, cookie: C) -> C {
        self.reader.cookie_set(cookie)
    }

    fn cookie_ref(&self) -> &C {
        self.reader.cookie_ref()
    }

    fn cookie_mut(&mut self) -> &mut C {
        self.reader.cookie_mut()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn mutable_reference() {
        use crate::Memory;
        const DATA : &[u8] = b"01234567890123456789suffix";
        let mut mem = Memory::new(DATA);

        /// API that consumes the memory reader.
        fn parse_ten_bytes<B: BufferedReader<()>>(mut r: B) {
            let d = r.data_consume_hard(10).unwrap();
            assert!(d.len() >= 10);
            assert_eq!(&d[..10], &DATA[..10]);
            drop(r); // We consumed the reader.
        }

        parse_ten_bytes(&mut mem as &mut dyn BufferedReader<()>);  // not as ergonomic as i wished tho
        parse_ten_bytes(mem.as_mut_reader());
        let suffix = mem.data_eof().unwrap();
        assert_eq!(suffix, b"suffix");
    }
}
