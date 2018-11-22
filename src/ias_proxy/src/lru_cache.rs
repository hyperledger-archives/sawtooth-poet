/*
 Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

/// module LruCache, for use by IAS proxy
use std::{borrow::BorrowMut,
          clone::Clone,
          cmp::{Eq,
                PartialEq},
          collections::{HashMap,
                        VecDeque},
          hash::Hash};

/// Generic structure representation of LRU cache,
/// Note key and value must implement the traits listed here.
#[derive(Debug, Clone)]
pub struct LruCache<K, V>
    where K: PartialEq + Eq + Hash + Clone,
          V: Clone {
    // Size of the LRU cache
    max_size: usize,
    // A list to note which key is accessed first, it should be locked before accessing
    order: VecDeque<K>,
    // Key value store, cached data
    values: HashMap<K, V>,
}

impl<K, V> LruCache<K, V>
    where K: PartialEq + Eq + Hash + Clone,
          V: Clone {
    /// Create a new instance of LRU cache, of generic type
    pub fn new(
        size: Option<usize>
    ) -> Self {
        let size = size.unwrap_or(100);
        LruCache {
            max_size: size,
            order: VecDeque::with_capacity(size),
            values: HashMap::new(),
        }
    }

    /// Sets the value passed for the key, LRU cache is a ordered hashmap that changes position
    /// of keys based on how frequently they are accessed.
    pub fn set(
        &mut self,
        key: K,
        value: V,
    ) {
        let ordered_keys = self.order.borrow_mut();
        let modified_values = self.values.borrow_mut();
        // Key not present, so add it
        if modified_values.contains_key(&key) == false {
            // Remove least accessed element from the LRU cache if there's no more space
            while ordered_keys.len() >= self.max_size {
                let popped = ordered_keys.pop_back();
                modified_values.remove(&popped.expect("Unable to pop from ordered list"));
            }
            modified_values.insert(key.clone(), value);
            ordered_keys.push_front(key);
        } else {
            // Rewrite with new value if Key is already present
            ordered_keys.retain(|element| { *element != key });
            modified_values.remove(&key);
            ordered_keys.push_front(key.clone());
            modified_values.insert(key, value);
        }
    }

    /// When a element is accessed from LRU cache, it is brought to front.
    pub fn get(
        &mut self,
        key: &K,
    ) -> Option<&V> {
        let ordered_keys = self.order.borrow_mut();
        let result = self.values.get(key);
        let to_return = match result {
            Some(found) => {
                // Remove element and re-insert it in front
                ordered_keys.retain(|element| { *element != *key });
                ordered_keys.push_front(key.clone());
                found
            }
            None => /* unexpected */ return None,
        };
        Option::from(to_return)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_SIZE: usize = 100;

    #[test]
    fn test_default_lru_cache_creation() {
        let default_lru_cache: LruCache<String, String> = LruCache::new(None);
        assert_eq!(default_lru_cache.max_size, DEFAULT_SIZE)
    }

    #[test]
    fn test_get_set_lru_cache() {
        let mut lru_cache: LruCache<String, String> = LruCache::new(Option::from(2));
        let key1 = "Key1".to_string();
        let key2 = "Key2".to_string();
        let value1 = "Value1".to_string();
        let value2 = "Value2".to_string();
        lru_cache.set(key1.clone(), value1.clone());
        lru_cache.set(key2.clone(), value2.clone());
        // expect element found would be Key2
        let lru_copy1 = lru_cache.clone();
        let found_element1 = lru_copy1.order.get(0).expect("Error reading inserted ele");
        assert_eq!(*found_element1, key2);
        let element_accessed1 = lru_cache.get(&key1).expect("Error reading inserted value").clone();
        assert_eq!(element_accessed1, value1);
        // expect element found would be Key1
        let lru_copy2 = lru_cache.clone();
        let found_element2 = lru_copy2.order.get(0).expect("Error reading inserted key");
        assert_eq!(*found_element2, key1);
        let element_accessed2 = lru_cache.get(&key2).expect("Error reading inserted value").clone();
        assert_eq!(element_accessed2, value2);
    }

    #[test]
    fn test_overwrite_existing_value() {
        let mut lru_cache: LruCache<String, String> = LruCache::new(Option::from(1));
        let key = "Key".to_string();
        let value1 = "Value1".to_string();
        let value2 = "Value2".to_string();
        lru_cache.set(key.clone(), value1.clone());
        let read_value =
            lru_cache.get(&key).expect("Value inserted but not present").clone();
        assert_eq!(read_value, value1);
        lru_cache.set(key.clone(), value2.clone());
        let read_value =
            lru_cache.get(&key).expect("Value inserted but not present").clone();
        assert_eq!(read_value, value2);
    }
}
