//
//  AtomicFlag.swift
//  Bastion
//
//  A minimal thread-safe one-shot latch. Used to coordinate a single-resume
//  CheckedContinuation across concurrently-executing closures (an NWConnection
//  state handler and a timeout Task) without mutating a captured `var`, which is
//  a data race under Swift's strict concurrency checking.
//

import Foundation

/// A one-shot flag. `takeFirst()` returns `true` for exactly one caller.
final class AtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var taken = false

    /// Atomically claims the flag. Returns `true` only for the first caller; `false` thereafter.
    func takeFirst() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if taken { return false }
        taken = true
        return true
    }
}
