# Configuration Options

## Pool Management

### pool.maxTotal

The maximum number of active objects that can be allocated from this pool at
the same time, or negative for no limit.

An invalid value is ignored.

Default: `8`

### pool.maxIdle

The maximum number of objects that can remain idle in the pool, without extra
ones being released, or negative for no limit.

Default: `8`

### pool.minIdle

The minimum number of objects that can remain idle in the pool, without extra
ones being created, or zero to create none.

Default: `0`

### pool.maxWaitMillis

The maximum number of milliseconds that the pool will block (when there are no
available objects) before throwing an exception when the pool is exhausted and
`pool.blockWhenExhausted` is `true`.

Set to `-1` to wait indefinitely.

Default: -1

### pool.testOnCreate

The indication of whether objects will be validated after creation. If the
object fails to validate, the borrow attempt that triggered the object creation
will fail.

Default: `false`

### pool.testOnBorrow

The indication of whether objects will be validated before being borrowed from
the pool. If the object fails to validate, it will be dropped from the pool,
and we will attempt to borrow another.

Default: `false`

### pool.testOnReturn

The indication of whether objects will be validated before being returned to
the pool.

Default: `false`

### pool.testWhileIdle

The indication of whether objects will be validated by the idle object evictor
(if any, see `pool.timeBetweenEvictionRunsMillis`). If an object fails to
validate, it will be dropped from the pool.

Default: `false`

### pool.timeBetweenEvictionRunsMillis

The number of milliseconds to sleep between runs of the idle object evictor
thread.

Set to `-1` to not run any idle object evictor thread.

Default: `-1`

### pool.numTestsPerEvictionRun

The maximum number of objects to examine during each run (if any) of the
idle object evictor thread. When positive, the number of tests performed
for a run will be the minimum of the configured value and the number of
idle instances in the pool. When negative, the number of tests performed
will be roughly one `n`th of the idle objects per run.

Default: `3`

### pool.minEvictableIdleTimeMillis

The minimum amount of time an object may sit idle in the pool before it is
eligible for eviction by the idle object evictor (if any, see
`pool.timeBetweenEvictionRunsMillis`). When non-positive, no objects will be
evicted from the pool due to idle time alone.

Default: `1800000` (30 minutes)

### pool.softMinEvictableIdleTimeMillis

The minimum amount of time a connection may sit idle in the pool before it is
eligible for eviction by the idle connection evictor, with the extra condition
that at least `pool.minIdle` objects remain in the pool.

When `pool.minEvictableIdleTimeMillis` is set to a positive value,
`pool.minEvictableIdleTimeMillis` is examined first by the idle connection
evictor - i.e. when idle objects are visited by the evictor, idle time is first
compared against `pool.minEvictableIdleTimeMillis` (without considering the
number of idle objects in the pool) and then against
`pool.softMinEvictableIdleTimeMillis`, including the `pool.minIdle` constraint.

Default: `-1`

### pool.evictionPolicyClassName

Sets the name of the eviction policy implementation that is used by this pool.
The pool will attempt to load the class using the thread context class loader.
If that fails, the pool will attempt to load the class using the class loader
that loaded this class.

The provided class must implement the
`org.apache.commons.pool2.impl.EvictionPolicy` interface.

Default: `org.apache.commons.pool2.impl.DefaultEvictionPolicy`

### pool.lifo

`True` means that the pool returns the most recently used ("last in") object
in the pool (if there are idle objects available). `False` means that the pool
behaves as a FIFO queue - objects are taken from the idle instance pool in the
order that they are returned to the pool.

Default: `true`

### pool.fairness

Indicates whether or not the pool serves threads waiting to borrow objects
fairly. `True` means that waiting threads are served as if waiting in a FIFO
queue.

Default: `false`

### pool.blockWhenExhausted

`True` means that the borrow methods blocks when the pool is exhausted (the
maximum number of "active" objects has been reached).

Default: `true`

### pool.jmxEnabled

`True` means that JMX will be enabled for newly created pools.

Default: `false`

### pool.jmxNamePrefix

Set the value of the JMX name prefix that will be used as part of the name
assigned to JMX enabled pools.

Default: `pool`

### pool.jmxNameBase

Set the value of the JMX name base that will be used as part of the name
assigned to JMX enabled pools created with this pool spec. A value of `null`
means that the pool will define the JMX name base.

Default: `null`
