import asyncio
import io
import time
import unittest

import pycache


class HelperTestCase(unittest.TestCase):

  def test_split_addr(self):
    self.assertEqual(pycache.split_addr('127.0.0.1:6000'), ('127.0.0.1', 6000))
    self.assertEqual(pycache.split_addr('localhost:8080'), ('localhost', 8080))
    self.assertEqual(pycache.split_addr('::1:9000'), ('::1', 9000))

  def test_current_time(self):
    t = pycache.current_time()
    self.assertIsInstance(t, int)
    self.assertGreater(t, 0)

  def test_dht_hash_and_alias(self):
    h1 = pycache.dht_hash('test_string')
    h2 = pycache.hash('test_string')
    self.assertEqual(h1, h2)
    self.assertIsInstance(h1, int)
    self.assertEqual(h1, pycache.dht_hash('test_string'))

  def test_distance(self):
    self.assertEqual(pycache.distance(10, 10), 0)
    self.assertEqual(pycache.distance(10, 5), pycache.distance(5, 10))
    self.assertEqual(pycache.distance(10, 5), 10 ^ 5)

  def test_closest(self):
    self.assertIsNone(pycache.closest([], 'key'))
    self.assertEqual(pycache.closest(['127.0.0.1:6000'], 'key'), '127.0.0.1:6000')

    peers = ['127.0.0.1:6000', '127.0.0.1:6001', '127.0.0.1:6002']
    c = pycache.closest(peers, 'my_test_key')
    self.assertIn(c, peers)

    # Verify that it strictly picks the minimum distance
    key_h = pycache.dht_hash('my_test_key')
    dists = [(pycache.distance(key_h, pycache.dht_hash(p)), p) for p in peers]
    expected = min(dists)[1]
    self.assertEqual(c, expected)

  def test_nr_helper(self):
    self.assertEqual(pycache.nr(True), ' noreply')
    self.assertEqual(pycache.nr(False), '')

  def test_dynamic_version(self):
    self.assertNotEqual(pycache.VERSION, 'unknown')
    self.assertEqual(pycache.VERSION, pycache.__version__)
    self.assertEqual(pycache.VERSION, '0.2.0')


class CacheTestCase(unittest.TestCase):

  def setUp(self):
    self.cache = pycache.LocalMemcachedClient({})

  def test_ht_set(self):
    # Insert value with an expiration time 60 seconds from now
    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() + 60, 'Hello, world!'))
    key, flags, data = self.cache.get('1')
    self.assertEqual(data, 'Hello, world!')

    # Insert value with an expiration time 60 seconds ago
    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() - 60, 'Hello, world!'))
    self.assertIsNone(self.cache.get('1'))

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
    self.assertIsNone(self.cache.get('1'))

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
    self.assertEqual('NOT_STORED\r\n', self.cache.append('missing', 'val'))

  def test_ht_prepend(self):
    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() + 60, 'world!'))
    key, flags, data = self.cache.get('1')
    self.assertEqual(data, 'world!')
    self.assertEqual('STORED\r\n', self.cache.prepend('1', 'Hello, '))
    key, flags, data = self.cache.get('1')
    self.assertEqual(data, 'Hello, world!')
    self.assertEqual('NOT_STORED\r\n', self.cache.prepend('missing', 'val'))

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
    self.assertEqual('NOT_FOUND\r\n', self.cache.decr('1', 1))

    self.assertEqual('STORED\r\n', self.cache.set('1', 0, time.time() + 60, '2'))
    self.assertEqual('1', self.cache.decr('1', 1).strip())
    self.assertEqual('0', self.cache.decr('1', 1).strip())
    key, flags, data = self.cache.get('1')
    self.assertEqual('0', data)

  def test_ht_non_numeric_incr_decr(self):
    self.cache.set('str_key', 0, 0, 'non_numeric')
    err_incr = self.cache.incr('str_key', 1)
    self.assertIn('CLIENT_ERROR cannot increment or decrement non-numeric value', err_incr)

    err_decr = self.cache.decr('str_key', 1)
    self.assertIn('CLIENT_ERROR cannot increment or decrement non-numeric value', err_decr)

  def test_ht_expired_mutation(self):
    # Set expired key
    self.cache.set('exp', 0, time.time() - 10, '10')
    self.assertEqual('NOT_FOUND\r\n', self.cache.incr('exp', 1))

    self.cache.set('exp2', 0, time.time() - 10, '10')
    self.assertEqual('NOT_FOUND\r\n', self.cache.decr('exp2', 1))

  def test_ht_items(self):
    self.cache.set('k1', 0, 0, 'v1')
    self.cache.set('k2', 0, 0, 'v2')
    items = self.cache.items()
    self.assertIsInstance(items, list)
    self.assertEqual(len(items), 2)
    # Mutating cache after items() does not affect returned list
    self.cache.delete('k1')
    self.assertEqual(len(items), 2)


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

  async def test_proto_multi_get(self):
    await self.client.set('k1', 0, 0, 'v1')
    await self.client.set('k2', 0, 0, 'v2')

    host, port = pycache.split_addr(self.addr)
    reader, writer = await asyncio.open_connection(host, port)
    try:
      writer.write(b'get k1 missing k2\r\n')
      await writer.drain()

      line1 = await reader.readline()
      data1 = await reader.readline()
      line2 = await reader.readline()
      data2 = await reader.readline()
      end_line = await reader.readline()

      self.assertEqual(line1, b'VALUE k1 0 2\r\n')
      self.assertEqual(data1, b'v1\r\n')
      self.assertEqual(line2, b'VALUE k2 0 2\r\n')
      self.assertEqual(data2, b'v2\r\n')
      self.assertEqual(end_line, b'END\r\n')
    finally:
      writer.close()
      await writer.wait_closed()

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

  async def test_proto_noreply_commands(self):
    # Test all noreply commands
    self.assertIsNone(await self.client.set('nr_key', 0, 0, 'val', noreply=True))
    self.assertIsNone(await self.client.replace('nr_key', 0, 0, 'val2', noreply=True))
    self.assertIsNone(await self.client.append('nr_key', 0, 0, '_app', noreply=True))
    self.assertIsNone(await self.client.prepend('nr_key', 0, 0, 'pre_', noreply=True))
    self.assertIsNone(await self.client.add('nr_new', 0, 0, '10', noreply=True))
    self.assertIsNone(await self.client.incr('nr_new', 2, noreply=True))
    self.assertIsNone(await self.client.decr('nr_new', 1, noreply=True))
    self.assertIsNone(await self.client.delete('nr_new', noreply=True))

  async def test_proto_data_size_mismatch(self):
    host, port = pycache.split_addr(self.addr)
    reader, writer = await asyncio.open_connection(host, port)
    try:
      for cmd in [
          b'set k 0 0 10\r\nshort\r\n',
          b'add k 0 0 10\r\nshort\r\n',
          b'replace k 0 0 10\r\nshort\r\n',
          b'append k 0 0 10\r\nshort\r\n',
          b'prepend k 0 0 10\r\nshort\r\n',
      ]:
        writer.write(cmd)
        await writer.drain()
        line = await reader.readline()
        self.assertEqual(line, b'CLIENT_ERROR data does not match size\r\n')
    finally:
      writer.close()
      await writer.wait_closed()

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
      self.assertTrue(line.startswith('VERSION {0}'.format(pycache.VERSION).encode('utf-8')))
    finally:
      writer.close()
      await writer.wait_closed()

  async def test_proto_verbosity(self):
    host, port = pycache.split_addr(self.addr)
    reader, writer = await asyncio.open_connection(host, port)
    try:
      writer.write(b'verbosity 1\r\n')
      await writer.drain()
      line = await reader.readline()
      self.assertEqual(line, b'OK\r\n')

      writer.write(b'verbosity 1 noreply\r\n')
      await writer.drain()

      writer.write(b'verbosity\r\n')
      await writer.drain()
      line2 = await reader.readline()
      self.assertTrue(line2.startswith(b'CLIENT_ERROR'))
    finally:
      writer.close()
      await writer.wait_closed()

  async def test_proto_join_leave_wire(self):
    join_res = await self.client.join('127.0.0.1:9999')
    self.assertEqual(join_res.strip(), 'OK')

    peers = await self.client.peers()
    self.assertIn('127.0.0.1:9999', peers)

    leave_res = await self.client.leave('127.0.0.1:9999')
    self.assertEqual(leave_res.strip(), 'OK')

    leave_res2 = await self.client.leave('127.0.0.1:9999')
    self.assertEqual(leave_res2.strip(), 'NOT_FOUND')

    self.assertIsNone(await self.client.leave('127.0.0.1:9999', noreply=True))

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

      # Syntax errors (wrong number of args)
      for malformed in [
          b'set key 0 0\r\n',
          b'delete\r\n',
          b'incr key\r\n',
          b'decr key\r\n',
          b'join\r\n',
          b'leave\r\n',
      ]:
        writer.write(malformed)
        await writer.drain()
        line = await reader.readline()
        self.assertTrue(line.startswith(b'CLIENT_ERROR'), f'Failed for {malformed}: {line}')
    finally:
      writer.close()
      await writer.wait_closed()

  async def test_proto_dump(self):
    # Test non-debug mode error
    host, port = pycache.split_addr(self.addr)
    reader, writer = await asyncio.open_connection(host, port)
    try:
      writer.write(b'dump\r\n')
      await writer.drain()
      line = await reader.readline()
      self.assertEqual(line, b'CLIENT_ERROR Not running in debug mode\r\n')
    finally:
      writer.close()
      await writer.wait_closed()

    # Test debug mode dump
    cache = pycache.LocalMemcachedClient({})
    debug_cs = pycache.CacheServer('127.0.0.1:0', cache, debug=True)
    server = await debug_cs.start()
    try:
      host, port = pycache.split_addr(debug_cs.addr)
      r, w = await asyncio.open_connection(host, port)
      try:
        w.write(b'set testkey 0 0 4\r\ntest\r\n')
        await w.drain()
        await r.readline()

        w.write(b'dump\r\n')
        await w.drain()
        lines = []
        while True:
          line = await r.readline()
          if line.strip() == b'END':
            break
          lines.append(line)
        self.assertTrue(any(b'testkey' in l for l in lines))
      finally:
        w.close()
        await w.wait_closed()
    finally:
      server.close()
      await server.wait_closed()

  async def test_proto_remote_client_malformed_responses(self):
    # Mock a server sending malformed get headers
    async def mock_handler(reader, writer):
      line = await reader.readline()
      if line.startswith(b'get bad_header'):
        writer.write(b'VALUE bad_header\r\n')
      elif line.startswith(b'get bad_end'):
        writer.write(b'VALUE bad_end 0 4\r\ndata\r\nBAD_END\r\n')
      await writer.drain()
      writer.close()
      await writer.wait_closed()

    server = await asyncio.start_server(mock_handler, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    client = pycache.RemoteMemcachedClient(f'127.0.0.1:{port}')
    try:
      with self.assertRaises(pycache.SyntaxError):
        await client.get('bad_header')
      with self.assertRaises(pycache.SyntaxError):
        await client.get('bad_end')
    finally:
      await client.close()
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

  async def test_server_leave_last_node(self):
    node = await self._create_node()
    node.cache.set('k', 0, 0, 'v')
    # Should not raise exception
    await node.leave()

  async def test_server_leave_unreachable_peer(self):
    node1 = await self._create_node()
    node2 = await self._create_node(peer=node1.addr)
    await asyncio.sleep(0.05)
    node2.cache.set('k', 0, 0, 'v')

    # Kill node1 server abruptly
    self.servers[0].close()
    await self.servers[0].wait_closed()

    # node2 should not crash when trying to notify dead node1
    await node2.leave()

  async def test_join_mesh_offline_peer(self):
    peers = set()
    # Port 1 is not open; should log error and not crash
    await pycache.join_mesh('127.0.0.1:1', '127.0.0.1:6000', peers)
    self.assertEqual(len(peers), 0)


class CliTestCase(unittest.IsolatedAsyncioTestCase):

  def test_cli_parsing(self):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--addr', default='127.0.0.1:6000')
    parser.add_argument('--peer', default=None)
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args(['--addr', '127.0.0.1:7000', '--debug', '--peer', '127.0.0.1:6000'])
    self.assertEqual(args.addr, '127.0.0.1:7000')
    self.assertEqual(args.peer, '127.0.0.1:6000')
    self.assertTrue(args.debug)

  async def test_main_execution_and_cancellation(self):
    task = asyncio.create_task(pycache.main(['--addr', '127.0.0.1:0', '--debug']))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
      await task
    except asyncio.CancelledError:
      pass


if __name__ == '__main__':
  unittest.main()

