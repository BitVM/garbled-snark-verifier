//! Storage for wire values keyed by `WireId` with a simple lifetime counter.
//!
//! Terminology
//! - Fanout (total): total number of downstream reads/uses a wire will have.
//! - Credits (remaining): the remaining read budget for a stored value; decremented on each read
//!   until it reaches 1, at which point the next read returns ownership and removes the entry.
//!
//! In this crate, component metadata computes fanout (a total), while runtime structures track
//! credits (the remaining counter). This module implements the latter.

use std::{fmt::Debug, marker::PhantomData, num::NonZero, ops::Deref};

use slab::Slab;
use tracing::{error, trace};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Can't find data with k = {key:?}")]
    NotFound { key: usize },
    #[error("Your credits overflow capacity")]
    OverflowCredits,
}

/// Remaining-use counter for stored values.
///
/// Notes
/// - The metadata pass computes per-wire fanout (a total expected use count).
/// - At runtime we track the remaining uses as "credits" and decrement on each read.
/// - Typical fanout counts are small; `u16` is sufficient here.
pub type Credits = u16;

#[derive(Debug, Clone)]
struct Entry<T: Default> {
    credits: NonZero<Credits>,
    data: T,
}

#[derive(Debug, Clone)]
pub struct Storage<K: From<usize>, T: Default> {
    data: Slab<Entry<T>>,
    index_offset: usize,
    _p: PhantomData<K>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Data<'l, T> {
    Borrowed(&'l T),
    Owned(T),
}

impl<'l, T> Deref for Data<'l, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(t) => t,
            Self::Owned(t) => t,
        }
    }
}

impl<'l, T: Clone> Data<'l, T> {
    pub fn to_owned(self) -> T {
        match self {
            Data::Owned(owned) => owned,
            Data::Borrowed(b) => b.clone(),
        }
    }
}

impl<K: Debug + Into<usize> + From<usize>, T: Default> Storage<K, T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Slab::with_capacity(capacity),
            index_offset: 2,
            _p: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Current allocated capacity of the underlying slab
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Test helper: check if a key currently exists in storage without consuming credits
    #[cfg(test)]
    pub fn contains(&self, key: K) -> bool {
        let index = self.to_index(key);
        self.data.get(index).is_some()
    }

    fn to_key(&self, index: usize) -> K {
        K::from(index + self.index_offset)
    }

    pub fn to_iter(self) -> impl Iterator<Item = (K, Credits, T)> {
        let offset = self.index_offset;
        self.data
            .into_iter()
            .map(move |(k, v)| (K::from(k + offset), v.credits.get(), v.data))
    }

    fn to_index(&self, k: K) -> usize {
        let index: usize = k.into();
        index.checked_sub(self.index_offset).unwrap()
    }

    /// Allocate a new entry with an initial remaining-use budget (`credits`).
    ///
    /// If `credits == 0`, returns a sentinel key and does not allocate.
    pub fn allocate(&mut self, data: T, credits: Credits) -> K {
        if let Some(credits) = NonZero::<Credits>::new(credits) {
            let before = self.data.capacity();
            let index = self.data.insert(Entry { data, credits });
            let after = self.data.capacity();

            if before != after {
                error!(" Capacity has grown from {before} to {after}");
            }

            self.to_key(index)
        } else {
            usize::MAX.into()
        }
    }

    /// Increase remaining-use budget for an existing entry.
    /// Errors with `OverflowCredits` if the counter would exceed `u16::MAX`.
    pub fn add_credits(&mut self, key: K, credits: Credits) -> Result<(), Error> {
        let index = self.to_index(key);

        let entry = self
            .data
            .get_mut(index)
            .ok_or(Error::NotFound { key: index })?;

        entry.credits = entry
            .credits
            .checked_add(credits)
            .ok_or(Error::OverflowCredits)?;

        Ok(())
    }

    /// Borrow the value under `key`, decrementing the remaining-use counter.
    ///
    /// Behavior
    /// - If the counter is 1, the final read returns ownership and removes the entry.
    /// - If the counter is >1, returns a borrowed reference and decrements by 1.
    pub fn get<'s>(&'s mut self, key: K) -> Result<Data<'s, T>, Error> {
        let index = self.to_index(key);

        match self.data.get(index) {
            None => Err(Error::NotFound { key: index }),
            Some(entry) if entry.credits == NonZero::<Credits>::MIN => {
                trace!("take {:?} from storage", self.to_key(index));
                let Entry { data, .. } = self.data.remove(index);
                Ok(Data::Owned(data))
            }
            Some(_) => {
                let entry: &'s mut Entry<T> = self.data.get_mut(index).expect("present above");

                // We know credits > 1 here.
                entry.credits = NonZero::<Credits>::new(entry.credits.get() - 1).unwrap();

                trace!("get {:?} from storage with -1 credit", index + 2);

                Ok(Data::Borrowed(&entry.data))
            }
        }
    }

    /// Modify the value under `key` in place.
    ///
    /// This does not change credits; callers are expected to manage remaining-use accounting
    /// via `get`/`add_credits`.
    pub fn set(&mut self, key: K, func: impl FnOnce(&mut T)) -> Result<(), Error> {
        let index = self.to_index(key);

        match self.data.get(index) {
            None => Err(Error::NotFound { key: index }),
            Some(_) => {
                // Mutate in place, decrement credits, return borrowed mut
                let entry = self.data.get_mut(index).expect("present above");
                // Decrement first to avoid borrow conflicts with entry.data
                func(&mut entry.data);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use test_log::test;

    use super::*;

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    struct Key(usize);

    impl From<usize> for Key {
        fn from(v: usize) -> Self {
            Key(v)
        }
    }

    impl From<Key> for usize {
        fn from(key: Key) -> usize {
            key.0
        }
    }

    #[test]
    fn get_borrow_then_owned() {
        let mut st = Storage::<Key, String>::new(8);
        st.index_offset = 0;
        let key = st.allocate("hello".to_string(), 2);

        {
            let d = st.get(key).expect("first get should succeed");
            match d {
                Data::Borrowed(s) => assert_eq!(s, "hello"),
                Data::Owned(_) => panic!("should not be owned yet"),
            }
        } // drop borrow

        // second get should consume last credit and remove
        let d2 = st.get(key).expect("second get should succeed");
        match d2 {
            Data::Owned(s) => assert_eq!(s, "hello"),
            Data::Borrowed(_) => panic!("should be owned now"),
        }

        // now it's removed
        let err = st.get(key).expect_err("should be NotFound");
        assert_eq!(err, Error::NotFound { key: key.0 });
    }

    #[test]
    fn get_owned_when_one_credit() {
        let mut st = Storage::<Key, i32>::new(4);
        st.index_offset = 0;
        let key = st.allocate(42, 1);

        let d = st.get(key).expect("get should succeed");
        match d {
            Data::Owned(v) => assert_eq!(v, 42),
            Data::Borrowed(_) => panic!("should be owned when single credit"),
        }

        // removed now
        assert_eq!(st.get(key), Err(Error::NotFound { key: key.0 }));
    }

    #[test]
    fn add_credits_and_overflow() {
        let mut st = Storage::<Key, i32>::new(4);
        let key = st.allocate(0, 1);

        // Increase to max (255)
        assert!(st.add_credits(key, Credits::MAX - 1).is_ok());

        // Now any additional credit should overflow
        let err = st.add_credits(key, 1).expect_err("expected overflow");
        assert_eq!(err, Error::OverflowCredits);
    }

    #[test]
    fn unknown_key_not_found() {
        let mut st = Storage::<Key, ()>::new(1);
        st.index_offset = 0;
        let fake = Key(123);
        assert_eq!(st.get(fake), Err(Error::NotFound { key: 123 }));
        assert_eq!(st.set(fake, |_| ()), Err(Error::NotFound { key: 123 }));
        assert_eq!(st.add_credits(fake, 1), Err(Error::NotFound { key: 123 }));
    }
}
