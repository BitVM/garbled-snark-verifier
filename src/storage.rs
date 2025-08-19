use std::{fmt::Debug, marker::PhantomData, num::NonZeroU32, ops::Deref};

use slab::Slab;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Can't find data with k = {key:?}")]
    NotFound { key: usize },
    #[error("Your credits overflow capacity")]
    OverflowCredits,
}

pub type Credits = NonZeroU32;
pub const ONE_CREDIT: Credits = NonZeroU32::MIN;

struct Entry<T: Default> {
    credits: Credits,
    data: T,
}

pub struct Storage<K: From<usize>, T: Default> {
    data: Slab<Entry<T>>,
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

impl<K: Debug + Into<usize> + From<usize>, T: Default> Storage<K, T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Slab::with_capacity(capacity),
            _p: PhantomData,
        }
    }

    pub fn allocate(&mut self, data: T, credits: Credits) -> K {
        K::from(self.data.insert(Entry { data, credits }))
    }

    pub fn add_credits(&mut self, key: K, credits: Credits) -> Result<(), Error> {
        let key = key.into();

        let entry = self.data.get_mut(key).ok_or(Error::NotFound { key })?;

        entry.credits = entry
            .credits
            .checked_add(credits.into())
            .ok_or(Error::OverflowCredits)?;

        Ok(())
    }

    /// Return value with `key`
    /// If value inside have one credit - value will be removed from storage
    pub fn get<'s>(&'s mut self, key: K) -> Result<Data<'s, T>, Error> {
        let key = key.into();

        match self.data.get(key) {
            None => Err(Error::NotFound { key }),
            Some(entry) if entry.credits == ONE_CREDIT => {
                let Entry { data, .. } = self.data.remove(key);
                Ok(Data::Owned(data))
            }
            Some(_) => {
                // We know credits > 1 here.
                let entry: &'s mut Entry<T> = self.data.get_mut(key).expect("present above");
                entry.credits = Credits::new(entry.credits.get() - 1).unwrap();
                Ok(Data::Borrowed(&entry.data))
            }
        }
    }

    /// Modify value under the `key`
    /// If value inside have one credit - value will be removed from storage
    pub fn get_with_mut<'s>(
        &'s mut self,
        key: K,
        func: impl FnOnce(&mut T),
    ) -> Result<Data<'s, T>, Error> {
        let key = key.into();

        match self.data.get(key) {
            None => Err(Error::NotFound { key }),
            Some(entry) if entry.credits == ONE_CREDIT => {
                let mut data = self.data.remove(key).data;
                func(&mut data);
                Ok(Data::Owned(data))
            }
            Some(_) => {
                // Mutate in place, decrement credits, return borrowed mut
                let entry = self.data.get_mut(key).expect("present above");
                // Decrement first to avoid borrow conflicts with entry.data
                entry.credits = Credits::new(entry.credits.get() - 1).unwrap();
                func(&mut entry.data);
                Ok(Data::Borrowed(&entry.data))
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
        let key = st.allocate("hello".to_string(), Credits::new(2).unwrap());

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
        let key = st.allocate(42, Credits::new(1).unwrap());

        let d = st.get(key).expect("get should succeed");
        match d {
            Data::Owned(v) => assert_eq!(v, 42),
            Data::Borrowed(_) => panic!("should be owned when single credit"),
        }

        // removed now
        assert_eq!(st.get(key), Err(Error::NotFound { key: key.0 }));
    }

    #[test]
    fn set_mutes_mutates_and_borrows_then_remove() {
        let mut st = Storage::<Key, String>::new(8);
        let key = st.allocate("abc".to_string(), Credits::new(2).unwrap());

        {
            let d = st
                .get_with_mut(key, |s| s.push('!'))
                .expect("set_mutes should succeed");
            match d {
                Data::Borrowed(s) => assert_eq!(s, "abc!"),
                Data::Owned(_) => panic!("should not be owned yet"),
            }
        }

        // Next access should remove and return owned
        match st.get(key).expect("should succeed") {
            Data::Owned(s) => assert_eq!(s, "abc!"),
            Data::Borrowed(_) => panic!("should be owned now"),
        }
    }

    #[test]
    fn set_mutes_owned_when_one_credit() {
        let mut st = Storage::<Key, String>::new(8);
        let key = st.allocate("x".to_string(), Credits::new(1).unwrap());

        match st
            .get_with_mut(key, |s| s.push('y'))
            .expect("set_mutes should succeed")
        {
            Data::Owned(s) => assert_eq!(s, "xy"),
            Data::Borrowed(_) => panic!("should be owned on last credit"),
        }

        // removed
        assert_eq!(st.get(key), Err(Error::NotFound { key: key.0 }));
    }

    #[test]
    fn add_credits_and_overflow() {
        let mut st = Storage::<Key, i32>::new(4);
        let key = st.allocate(0, Credits::new(1).unwrap());

        // Increase to max (255)
        assert!(
            st.add_credits(key, Credits::new(u32::MAX - 1).unwrap())
                .is_ok()
        );

        // Now any additional credit should overflow
        let err = st
            .add_credits(key, Credits::new(1).unwrap())
            .expect_err("expected overflow");
        assert_eq!(err, Error::OverflowCredits);
    }

    #[test]
    fn unknown_key_not_found() {
        let mut st = Storage::<Key, ()>::new(1);
        let fake = Key(123);
        assert_eq!(st.get(fake), Err(Error::NotFound { key: 123 }));
        assert_eq!(
            st.get_with_mut(fake, |_| ()),
            Err(Error::NotFound { key: 123 })
        );
        assert_eq!(
            st.add_credits(fake, Credits::new(1).unwrap()),
            Err(Error::NotFound { key: 123 })
        );
    }
}
