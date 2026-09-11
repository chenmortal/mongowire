//! The eager [`Array`].

use crate::error::Error;
use crate::raw::RawArray;
use crate::value::Bson;

/// A BSON array, eagerly materialized. BSON arrays are documents with
/// `"0"`, `"1"`, … keys; this type models them as a plain list.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Array {
    pub values: Vec<Bson>,
}

impl Array {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub fn push(&mut self, value: impl Into<Bson>) {
        self.values.push(value.into());
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Bson> {
        self.values.iter()
    }

    /// Encode into a raw array (keys `"0"`, `"1"`, …).
    ///
    /// # Errors
    /// [`Error::invalid`] if a string value contains interior NUL bytes.
    pub fn encode(&self) -> Result<RawArray, Error> {
        let mut out = Vec::new();
        crate::encode::encode_array(self, &mut out)?;
        RawArray::from_vec(out)
    }
}

impl FromIterator<Bson> for Array {
    fn from_iter<T: IntoIterator<Item = Bson>>(iter: T) -> Self {
        Self {
            values: iter.into_iter().collect(),
        }
    }
}

impl std::fmt::Display for Array {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::encode::log_array(self, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_iter_len() {
        let mut arr = Array::new();
        assert!(arr.is_empty());
        arr.push(1);
        arr.push("two");
        arr.push(Bson::Null);
        assert_eq!(arr.len(), 3);
        assert_eq!(
            arr.iter().collect::<Vec<_>>(),
            vec![&Bson::Int32(1), &Bson::String("two".to_owned()), &Bson::Null]
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut arr = Array::new();
        arr.push(Bson::Int32(-1));
        arr.push(Array::from_iter([Bson::String("inner".to_owned())]));

        let raw = arr.encode().unwrap();
        assert_eq!(raw.deep().unwrap(), arr);
        assert_eq!(raw.shallow().unwrap(), arr);
        assert_eq!(raw.deep().unwrap().encode().unwrap(), raw);
    }

    #[test]
    fn display() {
        let arr = Array::from_iter([Bson::Int32(1), Bson::Null]);
        assert_eq!(arr.to_string(), "[1, null]");
    }
}
