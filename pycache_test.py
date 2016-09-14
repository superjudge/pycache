# -*- coding: utf-8 -*-

import pycache
import unittest
import time


class CacheTestCase(unittest.TestCase):

  def setUp(self):
    self.cache = pycache.LocalMemcachedClient({})

  def tearDown(self):
    pass

  def test_ht_set(self):
    # Insert value with an expiration time 60 seconds from now
    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() + 60, 'Hello, world!'))
    key, flags, data = self.cache.get('1')
    self.assertEqual(data, 'Hello, world!')

    # Insert value with an expiration time 60 seconds ago
    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() - 60, 'Hello, world!'))
    self.assertEqual(self.cache.get('1'), None)

  def test_ht_delete(self):
    # Not possible to delete a non-existing key
    self.assertEqual('NOT_FOUND\r\n', self.cache.delete('1'))

    # Possible to delete an existing key, but only once
    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() + 60, 'Hello, world!'))
    self.assertEqual('DELETED\r\n', self.cache.delete('1'))
    self.assertEqual('NOT_FOUND\r\n', self.cache.delete('1'))

  def test_ht_add(self):
    # Add only works if key does not already exist
    self.assertEqual('STORED\r\n', self.cache.add('2', 0, time.time() + 60, 'Hello, world!'))
    self.assertEqual('NOT_STORED\r\n', self.cache.add('2', 0, time.time() + 60, 'Goodbye, world!'))

  def test_ht_replace(self):
    # Not possible to replace a non-existing key
    self.assertEqual('NOT_STORED\r\n', self.cache.replace('1', 0, time.time() + 60, 'Hello, world!'))
    self.assertEqual(None, self.cache.get('1'))

    # Possible to replace an existing key
    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() + 60, 'Hello, world!'))
    self.assertEqual('STORED\r\n', self.cache.replace('1', 0, time.time() + 60, 'Hello, world!'))

  def test_ht_append(self):
    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() + 60, 'Hello'))
    key, flags, data = self.cache.get('1')
    self.assertEqual(data, 'Hello')
    self.assertEqual('STORED\r\n', self.cache.append('1', ', world!'))
    key, flags, data = self.cache.get('1')
    self.assertEqual(data, 'Hello, world!')

  def test_ht_prepend(self):
    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() + 60, 'world!'))
    key, flags, data = self.cache.get('1')
    self.assertEqual(data, 'world!')
    self.assertEqual('STORED\r\n', self.cache.prepend('1', 'Hello, '))
    key, flags, data = self.cache.get('1')
    self.assertEqual(data, 'Hello, world!')

  def test_ht_incr(self):
    """Test increment and wrap-around to 0 at 2**64."""
    self.assertEqual('NOT_FOUND\r\n', self.cache.incr('1', 1))
    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() + 60, str(2**64 - 2)))
    self.assertEqual(str(2**64 - 1), self.cache.incr('1', 1).strip())
    key, flags, data = self.cache.get('1')
    self.assertEqual(str(2**64 - 1), data)

    self.assertEqual('0', self.cache.incr('1', 1).strip())
    key, flags, data = self.cache.get('1')
    self.assertEqual('0', data)

  def test_ht_decr(self):
    """Test decrement and min value 0."""
    # Can not decrement non-existing key/value
    self.assertEqual('NOT_FOUND\r\n', self.cache.decr('1', 1))

    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() + 60, '2'))
    self.assertEqual('1', self.cache.decr('1', 1).strip())
    self.assertEqual('0', self.cache.decr('1', 1).strip())
    key, flags, data = self.cache.get('1')
    self.assertEqual('0', data)


class ProtocolTestCase(unittest.TestCase):

  def setUp(self):
    #self.cache = pycache.CacheServer(None, None, {}, [])
    pass

  def tearDown(self):
    pass

  def test_proto_set(self):
    pass


if __name__ == '__main__':
  unittest.main()
