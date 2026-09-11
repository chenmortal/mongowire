//! Protocol IO helper traits — little-endian integers, cstrings and length
//! prefixes, read from byte slices and written into byte buffers.
//!
//! All upper layers (wirebson, mongowire) do their encoding/decoding through
//! these traits so that boundary checks are centralized and never panic.

use bytes::BytesMut;

/// Error returned while reading protocol primitives.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// Not enough input to satisfy the read.
    #[error("unexpected end of input: needed {needed} byte(s), got {got}")]
    ShortInput { needed: usize, got: usize },
    /// Input is structurally invalid (e.g. interior NUL where not allowed).
    #[error("invalid input: {0}")]
    Invalid(&'static str),
}

/// Error returned while writing protocol primitives.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    /// A string containing a NUL byte was passed where a cstring is required.
    #[error("string contains interior NUL byte")]
    NulInString,
}

pub type ReadResult<T, E = ReadError> = std::result::Result<T, E>;
pub type WriteResult<T, E = WriteError> = std::result::Result<T, E>;

/// Cursor-style reader over a borrowed byte slice.
///
/// Methods take `&mut self` and advance the slice on success; on error the
/// cursor is left untouched.
pub trait ProtocolRead<'a> {
    /// Consume and return exactly `n` bytes.
    ///
    /// # Errors
    /// [`ReadError::ShortInput`] if fewer than `n` bytes remain.
    fn read_bytes(&mut self, n: usize) -> ReadResult<&'a [u8]>;

    /// Number of bytes left in the cursor.
    fn remaining(&self) -> usize;

    /// Peek at the next 4 bytes as `i32` without advancing.
    ///
    /// # Errors
    /// [`ReadError::ShortInput`] if fewer than 4 bytes remain.
    fn peek_i32_le(&self) -> ReadResult<i32>;

    /// Consume one byte.
    ///
    /// # Errors
    /// [`ReadError::ShortInput`] if the cursor is empty.
    fn read_u8(&mut self) -> ReadResult<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Consume 4 bytes as a little-endian `i32`.
    ///
    /// # Errors
    /// [`ReadError::ShortInput`] if fewer than 4 bytes remain.
    fn read_i32_le(&mut self) -> ReadResult<i32> {
        let b = self.read_bytes(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Consume 4 bytes as a little-endian `u32`.
    ///
    /// # Errors
    /// [`ReadError::ShortInput`] if fewer than 4 bytes remain.
    fn read_u32_le(&mut self) -> ReadResult<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Consume 8 bytes as a little-endian `i64`.
    ///
    /// # Errors
    /// [`ReadError::ShortInput`] if fewer than 8 bytes remain.
    fn read_i64_le(&mut self) -> ReadResult<i64> {
        let b = self.read_bytes(8)?;
        Ok(i64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Consume 8 bytes as a little-endian `u64`.
    ///
    /// # Errors
    /// [`ReadError::ShortInput`] if fewer than 8 bytes remain.
    fn read_u64_le(&mut self) -> ReadResult<u64> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Consume a NUL-terminated string, returning its contents without the NUL.
    ///
    /// # Errors
    /// [`ReadError::ShortInput`] if no NUL byte is found.
    fn read_cstring(&mut self) -> ReadResult<&'a [u8]>;
}

impl<'a> ProtocolRead<'a> for &'a [u8] {
    fn read_bytes(&mut self, n: usize) -> ReadResult<&'a [u8]> {
        if self.len() < n {
            return Err(ReadError::ShortInput {
                needed: n,
                got: self.len(),
            });
        }
        let (head, tail) = self.split_at(n);
        *self = tail;
        Ok(head)
    }

    fn remaining(&self) -> usize {
        self.len()
    }

    fn peek_i32_le(&self) -> ReadResult<i32> {
        if self.len() < 4 {
            return Err(ReadError::ShortInput {
                needed: 4,
                got: self.len(),
            });
        }
        Ok(i32::from_le_bytes([self[0], self[1], self[2], self[3]]))
    }

    fn read_cstring(&mut self) -> ReadResult<&'a [u8]> {
        match self.iter().position(|&b| b == 0) {
            Some(pos) => {
                let (head, tail) = self.split_at(pos);
                *self = &tail[1..]; // skip the NUL
                Ok(head)
            }
            None => Err(ReadError::ShortInput {
                needed: self.len() + 1,
                got: self.len(),
            }),
        }
    }
}

/// Writer for protocol primitives into an owned byte buffer.
///
/// Implemented for `Vec<u8>` and `bytes::BytesMut`. Length-prefixed fields are
/// written by reserving a placeholder with [`ProtocolWrite::placeholder_i32`]
/// and patching it later with [`ProtocolWrite::put_i32_le_at`].
pub trait ProtocolWrite {
    /// Append a byte slice verbatim.
    fn put_bytes(&mut self, b: &[u8]);

    /// Append one byte.
    fn put_u8(&mut self, v: u8);

    /// Reserve space for `additional` more bytes.
    fn reserve(&mut self, additional: usize);

    /// Current number of bytes written.
    fn len(&self) -> usize;

    /// Whether nothing has been written yet.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Overwrite the byte at `pos`. Panics if `pos` is out of range — patching
    /// an unreserved placeholder is a programmer error.
    fn put_u8_at(&mut self, pos: usize, v: u8);

    /// Append a little-endian `i32`.
    fn put_i32_le(&mut self, v: i32) {
        self.put_bytes(&v.to_le_bytes());
    }

    /// Append a little-endian `u32`.
    fn put_u32_le(&mut self, v: u32) {
        self.put_bytes(&v.to_le_bytes());
    }

    /// Append a little-endian `i64`.
    fn put_i64_le(&mut self, v: i64) {
        self.put_bytes(&v.to_le_bytes());
    }

    /// Append a little-endian `u64`.
    fn put_u64_le(&mut self, v: u64) {
        self.put_bytes(&v.to_le_bytes());
    }

    /// Append a NUL-terminated string.
    ///
    /// # Errors
    /// [`WriteError::NulInString`] if `s` contains a NUL byte; nothing is written.
    fn put_cstring(&mut self, s: &str) -> WriteResult<()> {
        if s.as_bytes().contains(&0) {
            return Err(WriteError::NulInString);
        }
        self.put_bytes(s.as_bytes());
        self.put_u8(0);
        Ok(())
    }

    /// Reserve 4 bytes for a length prefix and return the placeholder offset.
    fn placeholder_i32(&mut self) -> usize {
        let pos = self.len();
        self.put_bytes(&[0, 0, 0, 0]);
        pos
    }

    /// Overwrite the `i32` at `pos` (little-endian). Panics if fewer than 4
    /// bytes are available at `pos`.
    fn put_i32_le_at(&mut self, pos: usize, v: i32) {
        let b = v.to_le_bytes();
        self.put_u8_at(pos, b[0]);
        self.put_u8_at(pos + 1, b[1]);
        self.put_u8_at(pos + 2, b[2]);
        self.put_u8_at(pos + 3, b[3]);
    }
}

impl ProtocolWrite for Vec<u8> {
    fn put_bytes(&mut self, b: &[u8]) {
        Vec::extend_from_slice(self, b);
    }

    fn put_u8(&mut self, v: u8) {
        Vec::push(self, v);
    }

    fn reserve(&mut self, additional: usize) {
        Vec::reserve(self, additional);
    }

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn put_u8_at(&mut self, pos: usize, v: u8) {
        self[pos] = v;
    }
}

impl ProtocolWrite for BytesMut {
    fn put_bytes(&mut self, b: &[u8]) {
        BytesMut::extend_from_slice(self, b);
    }

    fn put_u8(&mut self, v: u8) {
        bytes::BufMut::put_u8(self, v);
    }

    fn reserve(&mut self, additional: usize) {
        BytesMut::reserve(self, additional);
    }

    fn len(&self) -> usize {
        BytesMut::len(self)
    }

    fn put_u8_at(&mut self, pos: usize, v: u8) {
        self[pos] = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_scalars() {
        let mut r: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0xff, 0x00];
        assert_eq!(r.read_i32_le().unwrap(), 1);
        assert_eq!(r.read_u8().unwrap(), 0xff);
        assert_eq!(r.remaining(), 1);
        assert!(matches!(
            r.read_i32_le(),
            Err(ReadError::ShortInput { needed: 4, got: 1 })
        ));
    }

    #[test]
    fn read_cstring_ok_and_error() {
        let mut r: &[u8] = b"hello\0world\0rest";
        assert_eq!(r.read_cstring().unwrap(), b"hello");
        assert_eq!(r.read_cstring().unwrap(), b"world");
        assert_eq!(r, b"rest");
        assert!(r.read_cstring().is_err());
    }

    #[test]
    fn peek_does_not_advance() {
        let mut r: &[u8] = &[7, 0, 0, 0, 9];
        assert_eq!(r.peek_i32_le().unwrap(), 7);
        assert_eq!(r.remaining(), 5);
        assert_eq!(r.read_i32_le().unwrap(), 7);
    }

    #[test]
    fn write_scalars_and_patch() {
        let mut w = Vec::new();
        let pos = w.placeholder_i32();
        w.put_cstring("ab").unwrap();
        w.put_i32_le_at(pos, 3);
        assert_eq!(w, vec![3, 0, 0, 0, b'a', b'b', 0]);
    }

    #[test]
    fn write_cstring_rejects_nul() {
        let mut w = Vec::new();
        assert!(w.put_cstring("a\0b").is_err());
        assert!(w.is_empty());
    }
}
