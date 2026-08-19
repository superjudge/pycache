import asyncio
import time
import unittest

import pycache


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


class ProtocolTestCase(unittest.IsolatedAsyncioTestCase):

  async def asyncSetUp(self):
    self.cache = pycache.LocalMemcachedClient({})
    self.cs = pycache.CacheServer('127.0.0.1:0', self.cache)
    self.server = await self.cs.start()
    self.addr = self.cs.addr
    self.client = pycache.RemoteMemcachedClient(self.addr)

  async def asyncTearDown(self):
    await self.client.close()
    self.server.close()
    await self.server.wait_closed()

  async def test_proto_set_get(self):
    res = await self.client.set('greeting', 0, 0, 'Hello, async world!')
    self.assertEqual(res, 'STORED\r\n')

    val = await self.client.get('greeting')
    self.assertIsNotNone(val)
    key, flags, data = val
    self.assertEqual(key, 'greeting')
    self.assertEqual(flags, 0)
    self.assertEqual(data, 'Hello, async world!')

  async def test_proto_add(self):
    res = await self.client.add('unique_key', 0, 0, 'first')
    self.assertEqual(res, 'STORED\r\n')

    res2 = await self.client.add('unique_key', 0, 0, 'second')
    self.assertEqual(res2, 'NOT_STORED\r\n')

  async def test_proto_replace(self):
    res = await self.client.replace('missing_key', 0, 0, 'val')
    self.assertEqual(res, 'NOT_STORED\r\n')

    await self.client.set('existing_key', 0, 0, 'initial')
    res2 = await self.client.replace('existing_key', 0, 0, 'updated')
    self.assertEqual(res2, 'STORED\r\n')

    _, _, data = await self.client.get('existing_key')
    self.assertEqual(data, 'updated')

  async def test_proto_append_prepend(self):
    await self.client.set('concat', 0, 0, 'Middle')

    res_app = await self.client.append('concat', 0, 0, 'End')
    self.assertEqual(res_app, 'STORED\r\n')

    res_prep = await self.client.prepend('concat', 0, 0, 'Start')
    self.assertEqual(res_prep, 'STORED\r\n')

    _, _, data = await self.client.get('concat')
    self.assertEqual(data, 'StartMiddleEnd')

  async def test_proto_incr_decr(self):
    await self.client.set('counter', 0, 0, '10')

    incr_res = await self.client.incr('counter', 5)
    self.assertEqual(incr_res.strip(), '15')

    decr_res = await self.client.decr('counter', 3)
    self.assertEqual(decr_res.strip(), '12')

  async def test_proto_delete(self):
    await self.client.set('to_delete', 0, 0, 'temp')
    del_res = await self.client.delete('to_delete')
    self.assertEqual(del_res, 'DELETED\r\n')

    del_res2 = await self.client.delete('to_delete')
    self.assertEqual(del_res2, 'NOT_FOUND\r\n')

  async def test_proto_peers(self):
    peers_res = await self.client.peers()
    self.assertIn(self.addr, peers_res)

  async def test_proto_version(self):
    host, port = pycache.split_addr(self.addr)
    reader, writer = await asyncio.open_connection(host, port)
    try:
      writer.write(b'version\r\n')
      await writer.drain()
      line = await reader.readline()
      self.assertTrue(line.startswith(b'VERSION 0.1.0'))
    finally:
      writer.close()
      await writer.wait_closed()

  async def test_proto_unsupported_commands(self):
    host, port = pycache.split_addr(self.addr)
    reader, writer = await asyncio.open_connection(host, port)
    try:
      for cmd in [b'stats\r\n', b'flush_all\r\n', b'cas key 0 0 3 1\r\n', b'gets key\r\n']:
        writer.write(cmd)
        await writer.drain()
        line = await reader.readline()
        self.assertEqual(line, b'SERVER_ERROR command not implemented\r\n')
    finally:
      writer.close()
      await writer.wait_closed()

  async def test_proto_errors(self):
    host, port = pycache.split_addr(self.addr)
    reader, writer = await asyncio.open_connection(host, port)
    try:
      # Unknown command
      writer.write(b'invalidcommand\r\n')
      await writer.drain()
      line = await reader.readline()
      self.assertEqual(line, b'ERROR\r\n')

      # Syntax error (wrong number of args)
      writer.write(b'delete\r\n')
      await writer.drain()
      line = await reader.readline()
      self.assertTrue(line.startswith(b'CLIENT_ERROR'))
    finally:
      writer.close()
      await writer.wait_closed()

  async def test_proto_dump(self):
    # Test debug mode dump
    cache = pycache.LocalMemcachedClient({})
    debug_cs = pycache.CacheServer('127.0.0.1:0', cache, debug=True)
    server = await debug_cs.start()
    try:
      host, port = pycache.split_addr(debug_cs.addr)
      reader, writer = await asyncio.open_connection(host, port)
      try:
        writer.write(b'set testkey 0 0 4\r\ntest\r\n')
        await writer.drain()
        await reader.readline()

        writer.write(b'dump\r\n')
        await writer.drain()
        lines = []
        while True:
          line = await reader.readline()
          if line.strip() == b'END':
            break
          lines.append(line)
        self.assertTrue(any(b'testkey' in l for l in lines))
      finally:
        writer.close()
        await writer.wait_closed()
    finally:
      server.close()
      await server.wait_closed()

  async def test_proto_quit(self):
    async with pycache.RemoteMemcachedClient(self.addr) as c:
      await c.set('k', 0, 0, 'v')
      await c.quit()


class ClusterTestCase(unittest.IsolatedAsyncioTestCase):

  async def asyncSetUp(self):
    self.servers = []
    self.cache_servers = []

  async def _create_node(self, peer=None):
    cache = pycache.LocalMemcachedClient({})
    cs = pycache.CacheServer('127.0.0.1:0', cache, peer=peer)
    server = await cs.start()
    self.servers.append(server)
    self.cache_servers.append(cs)
    return cs

  async def asyncTearDown(self):
    for server in self.servers:
      server.close()
      await server.wait_closed()

  async def test_cluster_routing_and_handoff(self):
    import asyncio

    # Start node 1
    node1 = await self._create_node()

    # Start node 2 and join to node 1
    node2 = await self._create_node(peer=node1.addr)
    await asyncio.sleep(0.05)

    # Start node 3 and join to node 1
    node3 = await self._create_node(peer=node1.addr)
    await asyncio.sleep(0.05)

    # Verify peer connectivity
    async with pycache.RemoteMemcachedClient(node1.addr) as c1:
      peers = (await c1.peers()).split()
      self.assertIn(node1.addr, peers)
      self.assertIn(node2.addr, peers)
      self.assertIn(node3.addr, peers)

    # Store multiple keys via node 1 client
    test_keys = {'alpha': '111', 'beta': '222', 'gamma': '333', 'delta': '444', 'epsilon': '555'}
    async with pycache.RemoteMemcachedClient(node1.addr) as c1:
      for k, v in test_keys.items():
        res = await c1.set(k, 0, 0, v)
        self.assertEqual(res, 'STORED\r\n')

    # Verify all keys are retrievable from any node (e.g. node 3)
    async with pycache.RemoteMemcachedClient(node3.addr) as c3:
      for k, v in test_keys.items():
        val = await c3.get(k)
        self.assertIsNotNone(val, f"Key {k} should be found on cluster")
        self.assertEqual(val[2], v)

    # Gracefully shut down node 2 and verify key handover
    await node2.leave()

    # Verify all keys are still retrievable from node 1 or node 3
    async with pycache.RemoteMemcachedClient(node1.addr) as c1:
      for k, v in test_keys.items():
        val = await c1.get(k)
        self.assertIsNotNone(val, f"Key {k} should survive node departure")
        self.assertEqual(val[2], v)


if __name__ == '__main__':
  unittest.main()

