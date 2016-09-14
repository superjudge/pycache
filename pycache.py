# Copyright (c) 2011 Johan Liseborn <johan@liseborn.se>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import hashlib
import logging
import time

from gevent import Greenlet
from gevent.server import StreamServer
from gevent.socket import create_connection


VERSION = '0.1.0'


# This module contains an implementation of a DHT supporting a subset
# of the memcached protocol. This means that this module can be used
# as a drop-in replacement for memcached, backed by a DHT.
#
# The module contains both client- and server-side implementations of
# the memcached protocol. The implementation is not yet fully complete
# and compliant with the full memcached protocol.
#
# The DHT implementation is loosely based on Kademlia. We use the
# 160-bit SHA1 hash for consistent key hashing, and we use XOR to
# calculate the distance between two keys. We calculate the ID of each
# node (called a k-id or kid, for Kademlia ID) as the SHA1 hash of the
# nodes address string on the form '192.0.2.13:6000'; as we incude
# both the IP address and the port, it is possible to run multiple
# instances on the same physical or virtual server.
#
# The module uses gevent for lightweight threads and network
# communicaiton.
#
# The main classes and functions defined in this modue are:
#
# LocalMemcachedClient   A wrapper around a Python dictionary,
#                        offering a memcached-like interface
#
# RemoteMemcachedClient  A client supporting the TCP version
#                        of the memcached protocol. Offer the
#                        same interface as LocalMemcachedClient.
#
# CacheServer            A function object used together with
#                        the gevent StreamServer to listen for
#                        TCP connections. This class holds
#                        data that is common to a node, e.g.
#                        the local cache and the set of peers.
#
# CacheHandler           Used together with CacheServer to
#                        handle incoming connections. Each
#                        connection will have its own instance.
#                        This class implements the server-side
#                        of the memcached protocol, as well as
#                        the main parts of the actual DHT algorithm.
#
# JoinGreenlet           A greenlet that handles joining a new
#                        node to an existing mesh.
#
# There is also a set of helper functions to calculate the hash
# value of a string (i.e. the SHA1 hash of the string), the
# distance between to keys, and which node in a set of nodes
# is closest to a given key.


# The expiration time of a key/value in memcached# is specified either
# in Unix time (number of seconds since January 1, 1970), or as the
# number of seconds starting from the current time. In the latter
# case, the number may not exceed the following magic constant, which
# represents the number of seconds in 30 days.
MAX_RELATIVE_TIME = 60 * 60 * 24 * 30


# ----------------------------------------------------------------------------
# Memcached clients
#
# The LocalMemcachedClient and RemoteMemcachedClient both implement
# the same memcached-like interface. The return values of most of the
# methods can be used directly as answers in the memcached on-the-wire
# protocol.
#
# LocalMemcachedClient wraps a dictionary object, giving it an
# interface with memcached-like semantics.
#
# RemoteMemcachedClient implements the on-the-wire protocol of
# memcached and allows you to connect to a remote memcached server
# over TCP.

class LocalMemcachedClient(object):
  """A wrapper which gives a dict-like object a memcached-like interface.

  The values stored in the cache are three-tuples
  like (flags, exptime, data).

  Note that we do accept the 'noreply' argument in exactly the same
  way as for the remote memcached client. However, in this class
  we simply ignore it, as it does note really matter much if we
  return a result or not. The caller can just simply choose to
  ignore the reply.

  """

  STORED = 'STORED\r\n'
  NOT_STORED = 'NOT_STORED\r\n'
  NOT_FOUND = 'NOT_FOUND\r\n'
  DELETED = 'DELETED\r\n'

  def __init__(self, cache):
    """Initialize a local memcached client.

    cache :: Dictionary   A dict-like object where all key/value
                          pairs are stored

    """
    self.cache = cache

  def items(self):
    """Return a list with all items in our cache.

    The returned values are two-tuples
    like (key, (flags, exptime, data)).

    """
    return self.cache.items()

  def set(self, key, flags, exptime, value, noreply=False):
    """Set a key/value pair."""
    self.cache[key] = (flags, exptime, value)
    return self.STORED

  def add(self, key, flags, exptime, value, noreply=False):
    """Set a key/value pair, if key does not already exist."""
    if self.cache.has_key(key):
      return self.NOT_STORED
    else:
      return self.set(key, flags, exptime, value)

  def replace(self, key, flags, exptime, value, noreply=False):
    """Set a key/value pair, but only if key already exist."""
    if not self.cache.has_key(key):
      return self.NOT_STORED
    else:
      return self.set(key, flags, exptime, value)

  def append(self, key, value, noreply=False):
    """Append to value, if key/value pair exist."""
    if not self.cache.has_key(key):
      return self.NOT_STORED
    else:
      flags, exptime, old_value = self.cache[key]
      return self.set(key, flags, exptime, old_value + value)

  def prepend(self, key, value, noreply=False):
    """Prepend to value, if key/value pair exist."""
    if not self.cache.has_key(key):
      return self.NOT_STORED
    else:
      flags, exptime, old_value = self.cache[key]
      return self.set(key, flags, exptime, value + old_value)

  def incr(self, key, amount, noreply=False):
    """Increment value stored for key with amount.

    key :: String      The key for which we wish the increment
                       the value
    amount :: Integer  The amount with which we wish to increment
                       the value

    Returns the incremented value

    Throws ValueError if conversion from string to integer is not
    successful.

    Per the memcached protocol description, the value is interpreted
    as an unsigned 64 bit integer. The value will wrap around to zero
    again, when it reaches its maximum value.

    We always store all values as string, and thus we have to try to
    convert the value to an integer for incrementing. If successful,
    we will convert the value back to a string for storage when
    incremented.

    """
    if self.cache.has_key(key):
      flags, exptime, data = self.cache[key]

      if 0 == exptime or current_time() <= exptime:
        try:
          data = int(data)
        except ValueError:
          return 'CLIENT_ERROR cannot increment ' \
                 'or decrement non-numeric value\r\n'

        data += amount
        data = str(data % 2**64)
        self.cache[key] = (flags, exptime, data)

        return '{}\r\n'.format(data)
      else:
        del self.cache[key]

    return self.NOT_FOUND

  def decr(self, key, amount, noreply=False):
    """Decrement value stored for key with amount.

    key :: String      The key for which we wish the decrement
                       the value
    amount :: Integer  The amount with which we wish to decrement
                       the value

    Returns the decremented value

    Throws ValueError if conversion from string to integer is not
    successful.

    Per the memcached protocol description, the value is interpreted
    as an unsigned 64 bit integer. Decrementing to a negative value is
    thus not possible, and zero will be stored and returned in case
    the amount is larger than the value.

    We always store all values as string, and thus we have to try to
    convert the value to an integer for incrementing. If successful,
    we will convert the value back to a string for storage when
    incremented.

    """
    if self.cache.has_key(key):
      flags, exptime, data = self.cache[key]

      if 0 == exptime or current_time() <= exptime:
        try:
          data = int(data)
        except ValueError:
          return 'CLIENT_ERROR cannot increment ' \
                 'or decrement non-numeric value\r\n'

        data -= amount
        data = str(max(0, data))
        self.cache[key] = (flags, exptime, data)

        return '{}\r\n'.format(data)
      else:
        del self.cache[key]

    return self.NOT_FOUND

  def get(self, key):
    """Get value for a key."""
    if self.cache.has_key(key):
      flags, exptime, data = self.cache[key]

      if 0 == exptime or current_time() <= exptime:
        return (key, flags, data)
      else:
        del self.cache[key]
        return None
    else:
      return None

  def delete(self, key):
    """Delete a key/value pair."""
    if self.cache.has_key(key):
      del self.cache[key]
      return self.DELETED
    else:
      return self.NOT_FOUND


# ----------------------------------------------------------------------------
def nr(n):
  """Transform a booelan into a suitable 'noreply' string."""
  return ' noreply' if n else ''


# ----------------------------------------------------------------------------
class RemoteMemcachedClient(object):
  """A client for a subset of the memcached protocol.

  There are four basic set of commands, where all commands in a
  set share the same parameter format; commands in parenthesis are
  not supported:

    * set-type: set, add, replace, append, prepend, (cas)
    * incr-type: incr, decr
    * get-type: get, (gets)
    * join-type: join, leave

  """

  SET_TYPE = '{cmd} {key} {flags} {exptime} {bytes}{noreply}\r\n'
  INCR_TYPE = '{cmd} {key} {value}{noreply}\r\n'
  GET_TYPE = '{cmd} {key}\r\n'
  DELETE_TYPE = '{cmd} {key}{noreply}\r\n'
  PEERS_TYPE = '{cmd}\r\n'
  JOIN_TYPE = '{cmd} {addr}{noreply}\r\n'

  def __init__(self, addr):
    """Initialize a network based cache client.

    addr :: String   A string on the <ip-addr>:<port>,
                     e.g. '192.0.2.13:6000'

    Inititalization will create a TCP connection to the
    given IP address and port.

    """
    host, port = split_addr(addr)
    self.socket = create_connection((host, port))
    self.fd = self.socket.makefile()

  def _set_type(self, cmd, key, flags, exptime, data, noreply):
    """Send a set-type command over TCP."""
    self.fd.write(RemoteMemcachedClient.SET_TYPE.format(cmd=cmd,
                                                        key=key,
                                                        flags=flags,
                                                        exptime=exptime,
                                                        bytes=len(data),
                                                        noreply=nr(noreply)))
    self.fd.write('{}\r\n'.format(data))
    self.fd.flush()

    if not noreply:
      return self.fd.readline()

  def _incr_type(self, cmd, key, value, noreply):
    """Send an incr-type command over TCP."""
    self.fd.write(RemoteMemcachedClient.INCR_TYPE.format(cmd=cmd,
                                                         key=key,
                                                         value=value,
                                                         noreply=nr(noreply)))
    self.fd.flush()

    if not noreply:
      return self.fd.readline()

  def _join_type(self, cmd, addr, noreply):
    """Send a join-type command over TCP."""
    self.fd.write(RemoteMemcachedClient.JOIN_TYPE.format(cmd=cmd,
                                                         addr=addr,
                                                         noreply=nr(noreply)))
    self.fd.flush()

    if not noreply:
      return self.fd.readline()

  def _delete_type(self, cmd, key, noreply):
    """Send a delete-type command over TCP."""
    self.fd.write(RemoteMemcachedClient.DELETE_TYPE.format(cmd=cmd,
                                                           key=key,
                                                           noreply=nr(noreply)))
    self.fd.flush()

    if not noreply:
      return self.fd.readline()

  def _get_type(self, cmd, key):
    """Send a get-type command over TCP."""
    self.fd.write(RemoteMemcachedClient.GET_TYPE.format(cmd=cmd, key=key))
    self.fd.flush()

    # Read the first line of the response...
    line = self.fd.readline().strip()

    if line == 'END':
      return None

    try:
      _, _, flags, bytes = line.split()
    except ValueError:
      raise SyntaxError(line)

    # Read the second line of the response (should be the data).
    #
    # XXX: (mjl 2011-05-16) We chomp of the string to be 'bytes'
    #      bytes long (this should amount to chomping of the '\r\n'
    #      at the end of the string, but we do not actually check that).
    data = self.fd.readline()[:int(bytes)]

    # Read the 'END\r\n'...
    line = self.fd.readline().strip()

    if line != 'END':
      raise SyntaxError(line)

    return (key, flags, data)

  def _peers_type(self, cmd):
    """Send a peers-type command."""
    self.fd.write(RemoteMemcachedClient.PEERS_TYPE.format(cmd=cmd))
    self.fd.flush()
    return self.fd.readline()

  def set(self, key, flags, exptime, value, noreply=False):
    """Send a memcached set command."""
    return self._set_type('set', key, flags, exptime, value, noreply)

  def add(self, key, flags, exptime, value, noreply=False):
    """Send a memcached add command."""
    return self._set_type('add', flags, exptime, value, noreply)

  def replace(self, key, flags, exptime, value, noreply=False):
    """Send a memcached replace command."""
    return self._set_type('replace', key, flags, exptime, value, noreply)

  def append(self, key, flags, exptime, value, noreply=False):
    """Send a memcached append command."""
    return self._set_type('append', key, flags, exptime, value, noreply)

  def prepend(self, key, flags, exptime, value, noreply=False):
    """Send a memcached prepend command."""
    return self._set_type('prepend', key, flags, exptime, data, noreply)

  def incr(self, key, value, noreply=False):
    """Send a memcached incr command."""
    return self._incr_type('incr', key, value, noreply)

  def decr(self, key, value, noreply=False):
    """Send a memcached decr command."""
    return self._decr_type('decr', key, value, noreply)

  def get(self, key):
    """Send a memcached get command."""
    return self._get_type('get', key)

  def delete(self, key, noreply=False):
    """Send a memcached delete command."""
    return self._delete_type('delete', key, noreply)

  def quit(self):
    """Send a memcached quit command."""
    self.fd.write('quit\r\n')
    self.socket.close()

  def peers(self):
    """Send a memcached peers command."""
    return self._peers_type('peers')

  def join(self, addr, noreply=False):
    """Send a memcached join command."""
    return self._join_type('join', addr, noreply)

  def leave(self, addr, noreply=False):
    """Send a memcached leave command."""
    return self._join_type('leave', addr, noreply)


# ----------------------------------------------------------------------------
class SyntaxError(Exception):
  """Signal a memcached command syntax error."""


# ----------------------------------------------------------------------------
class CacheHandler(object):
  """The CacheHandler handles one socket connection from a client.

  A client may issue multiple commands in sequence over the same
  connection.

  The handler consist of three principle parts:

    1. The REPL which loops on accepting new commands from the client
    2. The argument parsing methods, which parse arguments for the
       different types of commands (the commands can be divided into a
       number of subsets with the same argument format).  These
       methods are called something like '_parse_XXX_args', where
       'XXX' is the name of the command, e.g. 'set'.
    3. The command methods, which implement the actual commands.
       There is one method for each command.  These methods are caled
       something like 'do_XXX', where 'XXX' is the name of the
       command, e.g. 'set'.

  """

  def __init__(self, socket, server):
    """Initialize a cache handler.

    socket :: Socket        The TCP socket connection object
    server :: CacheServer   The server object, which holds
                            data common to all connections of a
                            server

    """
    self.socket = socket
    self.rfile = self.wfile = self.socket.makefile()
    self.server = server

  def handle(self):
    """The REPL of the protocol stack.

    This method loops until a 'quit' command is issued, the
    connection is terminated by the client, or an internal server
    error occur, handling the commands sent from one client.

    """
    while True:
      line = self.rfile.readline().strip()

      if line:
        logging.info(line)

      if not line or line == 'quit':
        logging.info('client disconnected')
        break

      # The command lines in our protocol consist of
      # whitespace-separated strings terminated with '\r\n'. Each
      # command has two corresponding methods in this class, one to
      # parse the arguments into a dict (so that they can be used as
      # keyword arguments), and one that implements the actual
      # command. The methods have "magic" names, so that we can
      # determine which method to run from the name of the command
      # (e.g. for the "set" command, the two methods are called
      # "_parse_set_args" and "do_set").
      args = line.split()

      try:
        func = getattr(self, 'do_' + args[0])
        parse_args_func = getattr(self, '_parse_' + args[0] + '_args')
        func(**parse_args_func(args[1:]))
      except SyntaxError, e:
        self.wfile.write('CLIENT_ERROR {0}\r\n'.format(e))
      except AttributeError:
        self.wfile.write('ERROR\r\n')
      except:
        logging.exception('Internal server error')
        self.wfile.write('SERVER_ERROR\r\n')
        break

      self.wfile.flush()

  # --------------------------------------------------------------------------
  # Overlay Protocol: Rebalancing
  # --------------------------------------------------------------------------

  def rebalance(self, addr):
    """Check if any keys in this server should move to server at 'addr'.

    addr :: String   An address string on the form <ip-addr>:<port>,
                     e.g. '192.0.2.13:6000'.

    If any of the keys we store are closer to the ID of the new node
    than to our ID, the key should move to the new node.

    This method could be made more efficent, as we do not actually need
    to check our keys against the new ID if it is not closer to our ID
    than any of the other IDs of our peers. We have opted to keep
    the method simple, at the expense of efficiency.

    """
    self.server.peers.add(addr)

    for key, value in self.server.cache.items():
      addr = closest(self.server.peers.union([self.server.addr]), key)

      if addr != self.server.addr:
        flags, exptime, data = value

        RemoteMemcachedClient(addr).set(key, flags, exptime, data)

        self.server.cache.delete(key)

  # --------------------------------------------------------------------------
  # Overlay Protocol: Argument parsing methods
  # --------------------------------------------------------------------------

  def _parse_set_args(self, args):
    """Parse the arguments for a set-type command.

    The set-type commands are set, add, replace, append, and prepend.
    The argument list looks like:

    <command> <key> <flags> <exptime> <bytes> [noreply].

    args :: [String]   A list containing the arguments (in order)

    Returns a dict mapping each argument to its value.

    Raises a SyntaxError exception if we cannot parse the arguments.

    """
    if len(args) == 4:
      key, flags, exptime, length = args
      noreply = False
    elif len(args) == 5:
      key, flags, exptime, length, noreply = args
    else:
      raise SyntaxError('Wrong number of arguments')

    # Figure out if exptime is given as absolute or relative and adapt
    # as appropriate.
    exptime = int(exptime)

    if 0 < exptime <= MAX_RELATIVE_TIME:
      exptime = current_time() + exptime

    return { 'key': key
           , 'flags': int(flags)
           , 'exptime': exptime
           , 'length': int(length)
           , 'noreply': True if noreply else False
           }

  _parse_add_args = _parse_set_args
  _parse_replace_args = _parse_set_args
  _parse_append_args = _parse_set_args
  _parse_prepend_args = _parse_set_args

  def _parse_cas_type(self, args):
    """Parse the arguments for a cas-type command."""
    pass

  def _parse_get_args(self, args):
    """Parse the arguments for a get-type command."""
    return {'keys': args}

  _parse_gets_args = _parse_get_args

  def _parse_delete_args(self, args):
    """Parse the arguments for a delete-type command."""
    if len(args) == 1:
      key = args[0]
      noreply = False
    elif len(args) == 2:
      key, noreply = args
    else:
      raise SyntaxError('Wrong number of arguments')

    return {'key': key, 'noreply': True if noreply else False}

  def _parse_incr_args(self, args):
    """Parse the arguments of a incr-type command."""
    if len(args) == 2:
      key, value = args
      noreply = False
    elif len(args) == 3:
      key, value, noreply = args
    else:
      raise SyntaxError('Wrong number of arguments')

    return { 'key': key
           , 'value': int(value)
           , 'noreply': True if noreply else False
           }

  _parse_decr_args = _parse_incr_args

  def _parse_stats_args(self, args):
    """Parse the arguments of a stats-type command."""
    pass

  def _parse_flush_all_args(self, args):
    """Parse the arguments of a flush_all-type command."""
    pass

  def _parse_version_args(self, args):
    """Parse the arguments of a version-type command."""
    return {}

  def _parse_verbosity_args(self, args):
    """Parse the arguments of a verbosity-type command."""
    if len(args) == 1:
      level = args[0]
      noreply = False
    elif len(args) == 2:
      level, noreply = args
    else:
      raise SyntaxError('Wrong number of arguments')

    return {'level': int(level), 'noreply': True if noreply else False}

  def _parse_quit_args(self, args):
    """Parse the arguments of a quit-type command."""
    return {}

  _parse_peers_args = _parse_quit_args
  _parse_dump_args = _parse_quit_args

  def _parse_join_args(self, args):
    """Parse the arguments of a join-type command."""
    if len(args) == 1:
      addr = args[0]
      noreply = False
    elif len(args) == 2:
      addr, noreply = args
    else:
      raise SyntaxError('Wrong number of arguments')

    return {'addr': addr, 'noreply': True if noreply else False}

  _parse_leave_args = _parse_join_args

  # --------------------------------------------------------------------------
  # Overlay Protocol: Command methods
  # --------------------------------------------------------------------------

  def do_set(self, key, flags, exptime, length, noreply):
    """Store data in the cache.

    set <key> <flags> <exptime> <bytes> [noreply]

    """
    # FIXME: (mjl 2011-05-10) We should really read 'length' + 2 bytes
    #        and strip out the '\r\n'...
    data = self.rfile.readline().strip('\r\n')

    if length != len(data):
      self.rfile.write('CLIENT_ERROR data does not match size\r\n')
      return

    addr = closest(self.server.peers.union([self.server.addr]), key)

    if addr == self.server.addr:
      res = self.server.cache.set(key, flags, exptime, data)
    else:
      res = RemoteMemcachedClient(addr).set(key, flags, exptime, data)

    if not noreply:
      self.wfile.write(res)

  def do_add(self, key, flags, exptime, length, noreply):
    """Store data only if the server does not already hold data for
    this key.

    add <key> <flags> <exptime> <bytes> [noreply]

    """
    data = self.rfile.readline().strip('\r\n')

    if length != len(data):
      self.wfile.write('CLIENT_ERROR data does not match size\r\n')
      return

    addr = closest(self.server.peers.union([self.server.addr]), key)

    if addr == self.server.addr:
      res = self.server.cache.add(key, flags, exptime, data)
    else:
      res = RemoteMemcachedClient(addr).add(key, flags, exptime, data)

    if not noreply:
      self.wfile.write(res)

  def do_replace(self, key, flags, exptime, length, noreply):
    """Store data only if the server does already hold data for this
    key.

    replace <key> <flags> <exptime> <bytes> [noreply]

    """
    data = self.rfile.readline().strip('\r\n')

    if length != len(data):
      self.wfile.write('CLIENT_ERROR data does not match size\r\n')
      return

    addr = closest(self.server.peers.union([self.server.addr]), key)

    if addr == self.server.addr:
      res = self.server.cache.replace(key, flags, exptime, data)
    else:
      res = RemoteMemcachedClient(addr).replace(key, flags, exptime, data)

    if not noreply:
      self.wfile.write(res)

  def do_append(self, key, flags, exptime, length, noreply):
    """Add data to an existing key, after existing data.

    append <key> <flags> <exptime> <bytes> [noreply]

    """
    data = self.rfile.readline().strip('\r\n')

    if length != len(data):
      self.wfile.write('CLIENT_ERROR data does not match size\r\n')
      return

    addr = closest(self.server.peers.union([self.server.addr]), key)

    if addr == self.server.addr:
      res = self.server.cache.append(key, data)
    else:
      res = RemoteMemcachedClient(addr).append(key, flags, exptime, data)

    if not noreply:
      self.wfile.write(res)

  def do_prepend(self, key, flags, exptime, length, noreply):
    """Add data to an existing key, before existing data.

    prepend <key> <flags> <exptime> <bytes> [noreply]

    """
    data = self.rfile.readline().strip('\r\n')

    if length != len(data):
      self.wfile.write('CLIENT_ERROR data does not match size\r\n')
      return

    addr = closest(self.server.peers.union([self.server.addr]), key)

    if addr == self.server.addr:
      res = self.server.cache.prepend(key, data)
    else:
      res = RemoteMemcachedClient(addr).prepend(key, flags, exptime, data)

    if not noreply:
      self.wfile.write(res)

  def do_cas(self, *args):
    """Check and Set - Store data, but only if no one else has updated
    since I last fetched it.

    cas <key> <flags> <exptime> <bytes> <cas unique> [noreply]

    """
    self.wfile.write('SERVER_ERROR command not implemented\r\n')

  def do_get(self, keys):
    """Get value(s) for key(s).

    get <key>*

    """
    for key in keys:
      addr = closest(self.server.peers.union([self.server.addr]), key)

      if addr == self.server.addr:
        res = self.server.cache.get(key)
      else:
        res = RemoteMemcachedClient(addr).get(key)

      if res:
        key, flags, data = res

        self.wfile.write('VALUE {0} {1} {2}\r\n'.format(key,
                                                        flags,
                                                        len(data)))
        self.wfile.write('{0}\r\n'.format(data))

    self.wfile.write('END\r\n')

  def do_gets(self, keys):
    """Get value(s) for key(s).

    gets <key>*

    """
    self.wfile.write('SERVER_ERROR command not implemented\r\n')

  def do_delete(self, key, noreply):
    """Delete value stored for a specific key.

    delete <key> [noreply]

    """
    addr = closest(self.server.peers.union([self.server.addr]), key)

    if addr == self.server.addr:
      res = self.server.cache.delete(key)
    else:
      res = RemoteMemcachedClient(addr).delete(key)

    if not noreply:
      self.wfile.write(res)

  def do_incr(self, key, value, noreply):
    """Increment the stored value for the given key with the given
    amount.

    incr <key> <amount> [noreply]

    """
    addr = closest(self.server.peers.union([self.server.addr]), key)

    if addr == self.server.addr:
      res = self.server.cache.incr(key, value)
    else:
      res = RemoteMemcachedClient(addr).incr(key, value)

    if not noreply:
      self.wfile.write(res)

  def do_decr(self, key, value, noreply):
    """Decrement the stored value for the given key with the given
    amount.

    decr <key> <amount> [noreply]

    """
    addr = closest(self.server.peers.union([self.server.addr]), key)

    if addr == self.server.addr:
      res = self.server.cache.decr(key, value)
    else:
      res = RemoteMemcachedClient(addr).decr(key, value)

    if not noreply:
      self.wfile.write(res)

  def do_stats(self, *args):
    """Query about statistics.

    stats <args>

    """
    self.wfile.write('SERVER_ERROR command not implemented\r\n')

  def do_flush_all(self, exptime, noreply):
    """Flush all items from the cache.

    flush_all [exptime] [noreply]

    """
    self.wfile.write('SERVER_ERROR command not implemented\r\n')

  def do_version(self):
    """Return the version of the server."""
    self.file.write('VERSION {0} ({1})'.format(VERSION, self.kid))

  def do_verbosity(self, level, noreply):
    """Set the logging verbosity level."""
    logging.basicConfig(level=level * 10)

    if not noreply:
      self.wfile.write('OK\r\n')

  def do_quit(self):
    """Close the connection."""
    # This method is intentionally left blank.

  def do_dump(self):
    if self.server.debug:
      for key, value in self.server.cache.items():
        logging.debug('{0}:{1}'.format(key, value))
        self.wfile.write('{0}:{1}\r\n'.format(key, value))

      self.wfile.write('END\r\n')
    else:
      raise SyntaxError('Not running in debug mode')

  def do_peers(self):
    """Return all peer addresses, including our own."""
    self.wfile.write(' '.join(self.server.peers.union([self.server.addr])) + '\r\n')

  def do_join(self, addr, noreply):
    """Handle a new node joining the mesh."""
    if addr not in self.server.peers:
      self.rebalance(addr)

    logging.info('Peers {}'.format(self.server.peers))

    if not noreply:
      self.wfile.write('OK\r\n')

  def do_leave(self, addr, noreply):
    """Handle a node leaving the mesh."""
    if addr in self.server.peers:
      self.server.peers.remove(addr)
      res = 'OK\r\n'
    else:
      res = 'NOT_FOUND\r\n'

    logging.info('Server ID {0} peers {1}'.format(self.kid, self.peers))

    if not noreply:
      self.wfile.write(res)


# ----------------------------------------------------------------------------
class JoinGreenlet(Greenlet):
  def __init__(self, peer, addr, peers):
    """A greenlet used to join a node to a mesh.

    peer :: String        The address of one of the peers to the node
                          on the form '192.0.2.13:6001'.
    addr :: String        The address of the new node on the form
                          '192.0.2.13:6000'.
    peers :: Set(String)  A set of peers on the form '192.0.2.13:6001'.

    The peers set is normally an empty set when this greentlet
    is started. We will then add peers to that set according
    to the peers we recieve from the one peer we ask.

    """
    Greenlet.__init__(self)
    self.peer = peer
    self.addr = addr
    self.peers = peers

  def _run(self):
    # First we ask our peer for all the existing peers in the mesh...
    peers = RemoteMemcachedClient(self.peer).peers().split()

    # ...and then we join all those peers...
    for peer in peers:
      RemoteMemcachedClient(peer).join(self.addr, True)
      self.peers.add(peer)


# ----------------------------------------------------------------------------
class CacheServer(object):
  def __init__(self, addr, cache, peer, debug=False):
    """Create a cache listener.

    addr :: String        The address of this node. A string on the
                          form '192.0.2.13:6000'.
    cache :: Dictionary   The dictionary that will act as the local
                          store for this node.
    peer :: String        The address of one peer to this node on the
                          form <ip-addr>:<port>, e.g. '192.0.2.13:6001'.
    debug :: Boolean      True if we should run in debug mode, False otherwise

    """
    self.addr = addr
    self.kid = hash(addr)
    self.cache = cache
    self.peers = set()
    self.debug = debug

    if peer:
      JoinGreenlet.spawn(peer, addr, self.peers)

    logging.info('Server ID {0} @ {1} peers {2}'.format(self.kid,
                                                        self.addr,
                                                        self.peers))

  def __call__(self, socket, address):
    logging.info('New connection from {0[0]}:{0[1]}'.format(address))

    CacheHandler(socket, self).handle()

  def leave(self):
    """Have this node leave the mesh.

    This method first sends the leave command to all
    peers, so that they remove this node form their
    peer lists. Then we move our key/value pairs to
    the appropriate node still in the mesh.

    There is a reace condition here, if another node
    leaves at approximately the same time. That may lead
    to us believing that node is still part of the mesh,
    and trying to hand over key/value pairs to it. We do
    not currently handle that situation.

    """
    if not self.peers:
      logging.info('I am the last of my kind, my knowledge will be forever lost.')
      return

    for peer in self.peers:
      logging.info('Sending leave to {}'.format(peer))
      RemoteMemcachedClient(peer).leave(self.addr)

    for key, value in self.cache.items():
      flags, exptime, data = value
      addr = closest(self.peers, key)

      logging.info('Handing over {0}:{1} to {2}'.format(key, value, addr))

      RemoteMemcachedClient(addr).set(key, flags, exptime, data)


# ----------------------------------------------------------------------------
def split_addr(addr):
  """Split a string into host and port.

  addr :: String   A string on the form '192.0.2.13:4545'
                   or 'example.com:4545'

  returns a tuple (host :: String, port :: Integer), e.g. ('192.0.2.13', 4545)

  """
  (host, port) = addr.split(':')
  return (host, int(port))


# ----------------------------------------------------------------------------
def current_time():
  """Return current time in seconds since January 1, 1970."""
  return int(round(time.time()))


# ----------------------------------------------------------------------------
def hash(val):
  """Calculate the SHA1 hash of a value."""
  return int(hashlib.sha1(val).hexdigest(), 16)


# ----------------------------------------------------------------------------
def distance(a, b):
  """Calculate the distance between to keys like a xor b."""
  return a ^ b


# ----------------------------------------------------------------------------
def closest(peers, key):
  """
  Calculate which node among the peers have a k-id closest to the
  given key.

  Return the address of the node closest to the key in the form
  <ip-address>:<port>, e.g. '192.0.2.13:6000'.

  """
  if peers:
    dists = [(distance(hash(key), hash(x)), x) for x in peers]
    _, addr = min(dists)
    return addr
  else:
    return None


# ----------------------------------------------------------------------------
if __name__ == '__main__':
  import argparse

  parser = argparse.ArgumentParser(description='A DHT based caching server')
  parser.add_argument('--addr',
                      default='127.0.0.1:6000',
                      help='The address to listen on, e.g. 192.0.2.13:6000')
  parser.add_argument('--peer',
                      default=None,
                      help='The address of one peer, e.g. 192.0.2.13:6001')
  parser.add_argument('--version',
                      action='version',
                      version='%(prog)s {}'.format(VERSION),
                      help='Show version number')
  parser.add_argument('--debug',
                      action='store_true',
                      help='Run in debug mode')

  args = parser.parse_args()

  logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

  logging.info('Starting server @ {0}'.format(args.addr))

  cs =  CacheServer(args.addr, LocalMemcachedClient({}), args.peer, args.debug)
  server = StreamServer(split_addr(args.addr), cs)

  try:
    server.serve_forever()
  except KeyboardInterrupt:
    logging.info('Leaving mesh...')
    cs.leave()

# vim: sw=2 sts=2 et
