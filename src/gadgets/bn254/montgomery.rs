use std::ops::{Deref, DerefMut};

/// Generic Montgomery form marker
///
/// Wraps any field type to indicate it's in Montgomery form.
/// This provides compile-time type safety to prevent mixing
/// Montgomery and standard form operations.
///
/// # Examples
///
/// ```rust
/// // Montgomery<Fq> - Fq in Montgomery form
/// // Montgomery<Fq2> - Fq2 in Montgomery form  
/// // Montgomery<Fq6> - Fq6 in Montgomery form
/// // Montgomery<G1Projective> - G1 point with Montgomery coordinates
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Montgomery<T>(pub T);

impl<T> Montgomery<T> {
    /// Create a new Montgomery wrapper around the given value
    pub fn new(inner: T) -> Self {
        Montgomery(inner)
    }

    /// Extract the inner value from the Montgomery wrapper
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Map a function over the inner value
    pub fn map<U, F>(self, f: F) -> Montgomery<U>
    where
        F: FnOnce(T) -> U,
    {
        Montgomery(f(self.0))
    }

    /// Apply a function to the inner value and return the result
    pub fn with_inner<U, F>(&self, f: F) -> U
    where
        F: FnOnce(&T) -> U,
    {
        f(&self.0)
    }

    /// Apply a mutable function to the inner value and return the result
    pub fn with_inner_mut<U, F>(&mut self, f: F) -> U
    where
        F: FnOnce(&mut T) -> U,
    {
        f(&mut self.0)
    }
}

impl<T> Deref for Montgomery<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Montgomery<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> AsRef<T> for Montgomery<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> AsMut<T> for Montgomery<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_wrapper() {
        let value = 42u32;
        let mont = Montgomery::new(value);

        assert_eq!(mont.into_inner(), 42);
    }

    #[test]
    fn test_montgomery_map() {
        let mont = Montgomery::new(10u32);
        let mapped = mont.map(|x| x * 2);

        assert_eq!(mapped.into_inner(), 20);
    }

    #[test]
    fn test_montgomery_deref() {
        let mont = Montgomery::new(vec![1, 2, 3]);

        assert_eq!(mont.len(), 3);
        assert_eq!(mont[0], 1);
    }

    #[test]
    fn test_montgomery_with_inner() {
        let mont = Montgomery::new(String::from("hello"));
        let len = mont.with_inner(|s| s.len());

        assert_eq!(len, 5);
    }
}
