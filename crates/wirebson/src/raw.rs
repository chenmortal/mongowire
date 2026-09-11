//! Zero-copy raw composite values: [`RawDocument`] and [`RawArray`].
//!
//! Raw documents wrap a [`bytes::Bytes`] region sliced off a decoded wire
//! message — cloning and slicing are O(1) refcount operations, never copies.
//! Validation ([`RawDocument::from_bytes`], the Go `FindRaw` port) reads the
//! 4-byte length prefix and checks the trailing NUL without parsing fields.

use bytes::Bytes;

use mongo_common::bson::scalar::MIN_DOC_LEN;

use crate::error::Error;
use crate::raw_value::RawBsonRef;

/// A raw BSON document: validated bytes, no parsed fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawDocument(Bytes);

impl std::ops::Deref for RawDocument {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for RawDocument {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl RawDocument {
    /// Validate and wrap `b`.
    ///
    /// The slice must carry a 4-byte little-endian length (≥ 5) that matches
    /// the actual number of bytes exactly, and end with a NUL byte. Callers
    /// must slice a larger buffer to the document first.
    ///
    /// # Errors
    /// * [`Error::ShortInput`] — fewer than [`MIN_DOC_LEN`] bytes total.
    /// * [`Error::LengthMismatch`] — the declared length differs from
    ///   `b.len()` in either direction.
    /// * [`Error::invalid`] — declared length < 5, or the last byte is not NUL.
    pub fn from_bytes(b: Bytes) -> Result<Self, Error> {
        let actual = b.len();
        if actual < MIN_DOC_LEN {
            return Err(Error::ShortInput {
                needed: MIN_DOC_LEN,
                got: actual,
            });
        }

        let declared = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if declared < MIN_DOC_LEN {
            return Err(Error::invalid(
                0,
                format!("declared length {declared} is below the minimum {MIN_DOC_LEN}"),
            ));
        }
        if declared != actual {
            return Err(Error::LengthMismatch { declared, actual });
        }
        if b[actual - 1] != 0 {
            return Err(Error::invalid(actual - 1, "missing trailing NUL"));
        }

        Ok(Self(b))
    }

    /// [`Self::from_bytes`] for owned bytes.
    ///
    /// # Errors
    /// Same as [`Self::from_bytes`].
    pub fn from_vec(v: Vec<u8>) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(v))
    }

    /// The validated bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Consume into the underlying `Bytes`.
    pub fn into_bytes(self) -> Bytes {
        self.0
    }

    /// Decode shallowly: nested documents/arrays and code-with-scope scopes
    /// stay raw (Go `Decode()`).
    ///
    /// # Errors
    /// Any [`Error`] produced while walking the fields.
    pub fn shallow(&self) -> Result<crate::Document, Error> {
        crate::decode::decode_document(&self.0, crate::decode::Mode::Shallow, 1)
    }

    /// Decode fully recursively (Go `DecodeDeep()`).
    ///
    /// # Errors
    /// Any [`Error`] produced while walking the fields.
    pub fn deep(&self) -> Result<crate::Document, Error> {
        crate::decode::decode_document(&self.0, crate::decode::Mode::Deep, 1)
    }

    /// The raw value of the first field with this name.
    ///
    /// # Errors
    /// Malformed fields encountered before the match.
    pub fn get(&self, key: &str) -> Result<Option<RawBsonRef<'_>>, Error> {
        for item in self.fields() {
            let (name, value) = item?;
            if name == key {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    /// Iterate over `(name, raw value)` pairs.
    ///
    /// # Errors
    /// Returned per-item as iteration proceeds.
    pub fn fields(&self) -> FieldsIter<'_> {
        FieldsIter {
            scanner: crate::decode::Scanner::new(&self.0),
            done: false,
        }
    }

    /// The command name — the first field's name (Go `wirebson.Command()`).
    /// An empty (but valid) document yields an empty string.
    ///
    /// # Errors
    /// [`Error::ShortInput`] / [`Error::Utf8`] if the first field name is
    /// malformed.
    pub fn command(&self) -> Result<&str, Error> {
        let bytes = self.as_bytes();
        let body = bytes
            .get(4..)
            .ok_or(Error::ShortInput { needed: MIN_DOC_LEN, got: bytes.len() })?;
        let Some((&tag, name)) = body.split_first() else {
            return Ok("");
        };
        if tag == 0 {
            return Ok("");
        }
        let end = name
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::ShortInput {
                needed: bytes.len() + 1,
                got: bytes.len(),
            })?;
        Ok(std::str::from_utf8(&name[..end])?)
    }
}

impl std::fmt::Display for RawDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.shallow() {
            Ok(doc) => f.write_str(&crate::encode::log_document(&doc, f.alternate())),
            Err(e) => write!(f, "<invalid document: {e}>"),
        }
    }
}

/// A raw BSON array — bytes with the same shape as a document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawArray(Bytes);

impl std::ops::Deref for RawArray {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for RawArray {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl RawArray {
    /// Validate and wrap; same rules as [`RawDocument::from_bytes`].
    ///
    /// # Errors
    /// Same as [`RawDocument::from_bytes`].
    pub fn from_bytes(b: Bytes) -> Result<Self, Error> {
        // Same layout as a document.
        Ok(Self(RawDocument::from_bytes(b)?.into_bytes()))
    }

    /// [`Self::from_bytes`] for owned bytes.
    ///
    /// # Errors
    /// Same as [`RawDocument::from_bytes`].
    pub fn from_vec(v: Vec<u8>) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(v))
    }

    /// The validated bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Consume into the underlying `Bytes`.
    pub fn into_bytes(self) -> Bytes {
        self.0
    }

    /// Decode (arrays decode eagerly per element; composites follow the same
    /// shallow/deep rules).
    ///
    /// # Errors
    /// Any [`Error`] produced while walking the elements.
    pub fn shallow(&self) -> Result<crate::Array, Error> {
        crate::decode::decode_array(&self.0, crate::decode::Mode::Shallow, 1)
    }

    /// Decode fully recursively.
    ///
    /// # Errors
    /// Any [`Error`] produced while walking the elements.
    pub fn deep(&self) -> Result<crate::Array, Error> {
        crate::decode::decode_array(&self.0, crate::decode::Mode::Deep, 1)
    }
}

/// Iterator over a [`RawDocument`]'s fields.
pub struct FieldsIter<'a> {
    scanner: crate::decode::Scanner<'a>,
    done: bool,
}

impl<'a> Iterator for FieldsIter<'a> {
    type Item = Result<(&'a str, RawBsonRef<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.scanner.next() {
            Ok(Some(field)) => Some(Ok(field)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bson;

    /// The canonical `{"hello": "world"}` document from bsonspec.org.
    fn hello() -> Bytes {
        Bytes::from_static(&[
            0x16, 0x00, 0x00, 0x00, 0x02, b'h', b'e', b'l', b'l', b'o', 0x00, 0x06, 0x00, 0x00,
            0x00, b'w', b'o', b'r', b'l', b'd', 0x00, 0x00,
        ])
    }

    #[test]
    fn from_bytes_accepts_canonical_document() {
        let raw = RawDocument::from_bytes(hello()).unwrap();
        assert_eq!(raw.as_bytes().len(), 0x16);
        assert_eq!(raw.as_bytes(), &hello()[..]);
    }

    #[test]
    fn from_bytes_short_input() {
        for n in 0..MIN_DOC_LEN {
            assert_eq!(
                RawDocument::from_bytes(hello().slice(..n)),
                Err(Error::ShortInput { needed: MIN_DOC_LEN, got: n }),
                "n = {n}"
            );
        }
    }

    #[test]
    fn from_bytes_length_mismatch() {
        // Extra trailing bytes.
        let long = hello();
        let mut v = long.to_vec();
        v.push(0xaa);
        assert_eq!(
            RawDocument::from_vec(v),
            Err(Error::LengthMismatch { declared: 0x16, actual: 0x17 })
        );

        // A shorter region than declared (callers must slice first).
        assert_eq!(
            RawDocument::from_bytes(hello().slice(..0x15)),
            Err(Error::LengthMismatch { declared: 0x16, actual: 0x15 })
        );

        // Declared length smaller than the region.
        let mut v = hello().to_vec();
        v[0] = 0x15;
        assert_eq!(
            RawDocument::from_vec(v),
            Err(Error::LengthMismatch { declared: 0x15, actual: 0x16 })
        );
    }

    #[test]
    fn from_bytes_missing_nul_and_tiny_declared() {
        let mut v = hello().to_vec();
        let last = v.len() - 1;
        v[last] = 0x01;
        assert!(matches!(
            RawDocument::from_vec(v),
            Err(Error::InvalidInput { offset, .. }) if offset == last
        ));

        // Declared length below the minimum.
        let mut v = vec![0x00; 8];
        v[0] = 0x04;
        assert!(matches!(
            RawDocument::from_vec(v),
            Err(Error::InvalidInput { offset: 0, .. })
        ));
    }

    #[test]
    fn shallow_and_deep_agree() {
        let raw = RawDocument::from_bytes(hello()).unwrap();
        assert_eq!(raw.shallow().unwrap(), raw.deep().unwrap());
        assert_eq!(
            raw.get("hello").unwrap().unwrap().to_bson().unwrap(),
            Bson::String("world".to_owned())
        );
    }

    #[test]
    fn get_first_duplicate() {
        let mut doc = crate::Document::new();
        doc.add("a", 1);
        doc.add("a", 2);
        doc.add("b", 3);
        let raw = doc.encode().unwrap();

        assert_eq!(
            raw.get("a").unwrap().unwrap().to_bson().unwrap(),
            Bson::Int32(1)
        );
        assert_eq!(
            raw.get("b").unwrap().unwrap().to_bson().unwrap(),
            Bson::Int32(3)
        );
        assert!(raw.get("c").unwrap().is_none());
    }

    #[test]
    fn fields_iterates_in_order() {
        let mut doc = crate::Document::new();
        doc.add("one", 1);
        doc.add("two", "two");
        doc.add("three", true);
        let raw = doc.encode().unwrap();

        let fields: Vec<_> = raw.fields().collect::<Result<_, _>>().unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].0, "one");
        assert_eq!(fields[0].1, RawBsonRef::Int32(1));
        assert_eq!(fields[1].0, "two");
        assert_eq!(fields[1].1, RawBsonRef::String("two"));
        assert_eq!(fields[2].0, "three");
        assert_eq!(fields[2].1, RawBsonRef::Bool(true));

        // The iterator is fused and stops cleanly at the end.
        let mut it = raw.fields();
        for _ in 0..4 {
            it.next();
        }
        assert!(it.next().is_none());
    }

    #[test]
    fn fields_error_on_malformed() {
        // Nested document declaring more bytes than available.
        let bytes: Vec<u8> = [
            16u32.to_le_bytes().as_slice(),
            &[0x03, b'd', 0x00],
            64u32.to_le_bytes().as_slice(),
            5u32.to_le_bytes().as_slice(),
            &[0x00],
        ]
        .concat();
        let raw = RawDocument::from_vec(bytes).unwrap();
        assert!(raw.fields().next().unwrap().is_err());
    }

    #[test]
    fn command_names() {
        let raw = RawDocument::from_bytes(hello()).unwrap();
        assert_eq!(raw.command().unwrap(), "hello");

        let empty = RawDocument::from_vec(vec![5, 0, 0, 0, 0]).unwrap();
        assert_eq!(empty.command().unwrap(), "");

        // Non-UTF-8 first field name.
        let bytes: Vec<u8> = [9u32.to_le_bytes().as_slice(), &[0x0a, 0xff, 0xfe, 0x00], &[0x00]]
            .concat();
        let raw = RawDocument::from_vec(bytes).unwrap();
        assert!(matches!(raw.command(), Err(Error::Utf8(_))));
    }

    #[test]
    fn raw_array_roundtrip() {
        let arr = crate::Array::from_iter([Bson::Int32(7), Bson::Null]);
        let raw = RawArray::from_vec(arr.encode().unwrap().into_bytes().to_vec()).unwrap();
        assert_eq!(raw.shallow().unwrap(), arr);
        assert_eq!(raw.deep().unwrap(), arr);
        // 4 len + [i32 element] + [null element] + term.
        assert_eq!(raw.as_bytes().len(), 4 + 7 + 3 + 1);
    }

    #[test]
    fn display() {
        let mut doc = crate::Document::new();
        doc.add("hello", "world");
        doc.add("n", 42);
        let raw = doc.encode().unwrap();
        assert_eq!(raw.to_string(), r#"{"hello": "world", "n": 42}"#);
        assert_eq!(
            format!("{raw:#}"),
            "{\n  \"hello\": \"world\",\n  \"n\": 42,\n}"
        );
    }
}
