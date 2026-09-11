//! The eager [`Document`]: an ordered list of [`Field`]s.

use crate::error::Error;
use crate::raw::RawDocument;
use crate::value::Bson;

/// A BSON document, eagerly materialized.
///
/// Field order is preserved and duplicate names are allowed (matching the Go
/// reference); [`Document::get`] returns the first match.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Document {
    pub(crate) fields: Vec<Field>,
}

/// A single name → value entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: String,
    pub value: Bson,
}

impl Document {
    /// An empty document.
    pub fn new() -> Self {
        Self { fields: Vec::new() }
    }

    /// Number of fields (counting duplicates).
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Add a field, keeping duplicates.
    pub fn add(&mut self, name: impl Into<String>, value: impl Into<Bson>) {
        self.fields.push(Field {
            name: name.into(),
            value: value.into(),
        });
    }

    /// The first field with this name.
    pub fn get(&self, name: &str) -> Option<&Bson> {
        self.fields.iter().find(|f| f.name == name).map(|f| &f.value)
    }

    /// The first field with this name, mutably.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Bson> {
        self.fields
            .iter_mut()
            .find(|f| f.name == name)
            .map(|f| &mut f.value)
    }

    /// Remove every field with this name; returns the first removed value.
    pub fn remove(&mut self, name: &str) -> Option<Bson> {
        let mut first = None;
        let mut i = 0;
        while i < self.fields.len() {
            if self.fields[i].name == name {
                let field = self.fields.remove(i);
                if first.is_none() {
                    first = Some(field.value);
                }
            } else {
                i += 1;
            }
        }
        first
    }

    /// Replace the value of the first field with this name, or append a new
    /// field if absent.
    pub fn replace(&mut self, name: impl Into<String>, value: impl Into<Bson>) {
        let name = name.into();
        let value = value.into();
        for field in &mut self.fields {
            if field.name == name {
                field.value = value;
                return;
            }
        }
        self.fields.push(Field { name, value });
    }

    /// Iterate over fields in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Bson)> {
        self.fields.iter().map(|f| (f.name.as_str(), &f.value))
    }

    /// Field names in order (duplicates included).
    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|f| f.name.as_str())
    }

    /// The command name: the first field's name (Go `wirebson.Command()`).
    /// `None` if the document is empty.
    pub fn command(&self) -> Option<&str> {
        self.fields.first().map(|f| f.name.as_str())
    }

    /// Encode into a raw document.
    ///
    /// # Errors
    /// [`Error::invalid`] if a string field contains interior NUL bytes.
    pub fn encode(&self) -> Result<RawDocument, Error> {
        let mut out = Vec::new();
        crate::encode::encode_document(self, &mut out)?;
        RawDocument::from_vec(out)
    }
}

impl FromIterator<Field> for Document {
    fn from_iter<T: IntoIterator<Item = Field>>(iter: T) -> Self {
        Self {
            fields: iter.into_iter().collect(),
        }
    }
}

/// Convenience: build a document from `(name, value)` pairs.
impl<K: Into<String>, V: Into<Bson>> FromIterator<(K, V)> for Document {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self {
            fields: iter
                .into_iter()
                .map(|(k, v)| Field {
                    name: k.into(),
                    value: v.into(),
                })
                .collect(),
        }
    }
}

impl std::fmt::Display for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::encode::log_document(self, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Array;

    #[test]
    fn get_get_mut() {
        let mut doc = Document::new();
        doc.add("a", 1);
        doc.add("b", "x");
        doc.add("a", 2); // duplicate

        assert_eq!(doc.get("a"), Some(&Bson::Int32(1)));
        assert_eq!(doc.get("b"), Some(&Bson::String("x".to_owned())));
        assert_eq!(doc.get("c"), None);

        if let Some(v) = doc.get_mut("b") {
            *v = Bson::Int64(9);
        }
        assert_eq!(doc.get("b"), Some(&Bson::Int64(9)));
        assert_eq!(doc.get_mut("c"), None);
    }

    #[test]
    fn remove_all_duplicates() {
        let mut doc = Document::new();
        doc.add("a", 1);
        doc.add("b", 2);
        doc.add("a", 3);
        doc.add("a", 4);

        assert_eq!(doc.remove("a"), Some(Bson::Int32(1)));
        assert_eq!(doc.len(), 1);
        assert_eq!(doc.get("a"), None);
        assert_eq!(doc.remove("a"), None);
        assert_eq!(doc.get("b"), Some(&Bson::Int32(2)));
    }

    #[test]
    fn replace_existing_or_append() {
        let mut doc = Document::new();
        doc.add("a", 1);

        doc.replace("a", "replaced");
        assert_eq!(doc.len(), 1);
        assert_eq!(doc.get("a"), Some(&Bson::String("replaced".to_owned())));

        doc.replace("b", 2);
        assert_eq!(doc.len(), 2);
        assert_eq!(doc.get("b"), Some(&Bson::Int32(2)));

        // Replacing keeps the original position.
        assert_eq!(doc.field_names().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn command_and_iter() {
        let empty = Document::new();
        assert_eq!(empty.command(), None);
        assert!(empty.is_empty());

        let mut doc = Document::new();
        doc.add("insert", 1);
        doc.add("other", 2);
        assert_eq!(doc.command(), Some("insert"));
        assert_eq!(
            doc.iter().collect::<Vec<_>>(),
            vec![("insert", &Bson::Int32(1)), ("other", &Bson::Int32(2))]
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut doc = Document::new();
        doc.add("hello", "world");
        doc.add("arr", Array::from_iter([Bson::Bool(true), Bson::Null]));
        doc.add("dup", 1);
        doc.add("dup", 2);

        let raw = doc.encode().unwrap();
        assert_eq!(raw.deep().unwrap(), doc);

        // Byte-exact re-encoding.
        assert_eq!(raw.deep().unwrap().encode().unwrap(), raw);
    }

    #[test]
    fn from_iterator_pairs() {
        let doc = Document::from_iter([("a", Bson::Int32(1)), ("b", Bson::from("two"))]);
        assert_eq!(doc.len(), 2);
        assert_eq!(doc.get("a"), Some(&Bson::Int32(1)));
        assert_eq!(doc.get("b"), Some(&Bson::String("two".to_owned())));
    }

    #[test]
    fn display() {
        let mut doc = Document::new();
        doc.add("a", 1);
        assert_eq!(doc.to_string(), r#"{"a": 1}"#);
    }
}
