// Sections covering implementation, security analysis, and distributed-systems considerations.
const H = require("./wp_helpers");
const {
  p, h1, h2, h3, code, callout, bullet, numbered, table, spacer,
  ic, tx, bold, it, Paragraph, TextRun,
} = H;

function buildHow() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART V: How to Implement
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part V: How to Implement"));

  out.push(p([
    tx("This part is the implementer's guide. It walks through the two generation algorithms, the decoder, the edge cases that distinguish a correct implementation from a buggy one, and recommended configuration patterns. Reference implementations in Python, Go, Rust, and TypeScript appear in Part IX; this part describes the algorithms abstractly."),
  ]));

  out.push(h2("The Standard Generator"));

  out.push(p([
    tx("The Standard generator (variant 0x01) maintains two pieces of state per generator instance: the timestamp of the last ID it produced (last_ts) and the counter value used in that ID (counter). Both start at zero. The algorithm for producing a new ID is:"),
  ]));

  out.push(spacer());

  out.push(code(
    "function standard_new_id():\n" +
    "    rnd ← csprng(33 bytes)               # 1 step byte + 32-byte tail\n" +
    "    ts  ← now_ms()\n" +
    "\n" +
    "    if ts < last_ts:                     # clock went backward\n" +
    "        ts ← last_ts                     # clamp to preserve monotonicity\n" +
    "\n" +
    "    if ts == last_ts:                    # same ms as previous ID\n" +
    "        step    ← 1 + (rnd[0] & 0x0F)    # random step in [1, 16]\n" +
    "        counter ← counter + step\n" +
    "        if counter > 0xFFFF:             # counter overflow\n" +
    "            spin until now_ms() > ts\n" +
    "            ts      ← now_ms()\n" +
    "            counter ← rnd[0]             # reseed at small random offset\n" +
    "    else:                                # new ms\n" +
    "        counter ← rnd[0]                 # randomized starting offset\n" +
    "\n" +
    "    last_ts ← ts\n" +
    "    return BIG_ENDIAN_48(ts) || 0x01 || BIG_ENDIAN_16(counter) || rnd[1..33]"
  ));

  out.push(p([
    tx("Three subtle behaviors are worth highlighting:"),
  ]));

  out.push(p([
    bold("Clock clamping. "),
    tx("If the wall clock moves backward (NTP [14] correction, leap second, system clock adjustment), we use the last-known timestamp instead. This preserves local monotonicity at the cost of generating IDs whose timestamps are slightly ahead of the actual wall clock for as long as the regression lasts. This is the right tradeoff: a non-monotonic ID stream breaks B-tree indexes, replication ordering, and human intuition; a brief future-skew of a few hundred milliseconds is invisible to virtually all consumers."),
  ]));

  out.push(p([
    bold("Random counter starting point. "),
    tx("When we enter a new millisecond, we don't reset the counter to 0; we reset it to a random 8-bit value from rnd[0]. This means the counter values across two consecutive milliseconds are unrelated, which prevents an outside observer from estimating a generator's throughput just by sampling consecutive IDs."),
  ]));

  out.push(p([
    bold("Spin on overflow. "),
    tx("If the counter exhausts within a single millisecond, the algorithm busy-waits until the wall clock ticks over. This is a hard cap of 65,536 IDs per millisecond per generator (~65M IDs/s); on commodity hardware, this is a generous upper bound that we have not been able to hit even under synthetic load. If your workload approaches this limit, run more generators in parallel — they don't need to coordinate."),
  ]));

  out.push(callout(
    "Thread safety",
    "The Standard generator is NOT internally locked. Each thread should hold its own generator instance, OR external code should serialize access to a shared instance. The reasoning is that lock-free per-thread generation is significantly faster than mutex-protected shared generation, and most real workloads can naturally allocate one generator per worker. The tradeoff is that two generator instances on the same machine, in the same millisecond, can produce two IDs whose timestamp+variant+counter prefixes happen to collide; the 256-bit random tail then breaks the tie. The probability of a tail collision under any realistic workload is vanishing.",
    "info",
  ));

  out.push(h2("The HLC Generator"));

  out.push(p([
    tx("The HLC generator (variant 0x02) maintains two pieces of state: the logical time l (always at least the maximum of any wall clock or peer HLC the generator has observed) and the logical counter c. The algorithm for producing a new ID, optionally observing a peer's HLC, is:"),
  ]));

  out.push(spacer());

  out.push(code(
    "function hlc_new_id(observe = None):\n" +
    "    rnd ← csprng(32 bytes)\n" +
    "    pt  ← now_ms()                       # physical time\n" +
    "\n" +
    "    LOCK\n" +
    "        l_old, c_old ← l, c\n" +
    "\n" +
    "        if observe is not None:\n" +
    "            l_msg ← observe.timestamp\n" +
    "            c_msg ← observe.counter\n" +
    "            if l_msg - pt > HLC_MAX_DRIFT_MS:\n" +
    "                raise HLCDriftError\n" +
    "            l_new ← max(l_old, l_msg, pt)\n" +
    "            if l_new == l_old == l_msg:\n" +
    "                c_new ← max(c_old, c_msg) + 1\n" +
    "            else if l_new == l_old:\n" +
    "                c_new ← c_old + 1\n" +
    "            else if l_new == l_msg:\n" +
    "                c_new ← c_msg + 1\n" +
    "            else:\n" +
    "                c_new ← 0\n" +
    "        else:\n" +
    "            l_new ← max(l_old, pt)\n" +
    "            c_new ← (c_old + 1) if l_new == l_old else 0\n" +
    "\n" +
    "        if c_new > 0xFFFF:                # counter overflow\n" +
    "            l_new ← l_new + 1             # bump logical time\n" +
    "            c_new ← 0\n" +
    "\n" +
    "        l, c ← l_new, c_new\n" +
    "    UNLOCK\n" +
    "\n" +
    "    return BIG_ENDIAN_48(l_new) || 0x02 || BIG_ENDIAN_16(c_new) || rnd"
  ));

  out.push(p([
    tx("Compared to the Standard generator, three things change:"),
  ]));

  out.push(p([
    bold("The lock is mandatory. "),
    tx("HLC requires atomic read-modify-write of (l, c) to preserve correctness — two threads racing to update the HLC would create logical-time inversions that break causality. Implementations MUST serialize the update. High-contention workloads should shard HLC state across multiple instances, with the understanding that each instance becomes its own causal domain (more on this in Part VII)."),
  ]));

  out.push(p([
    bold("Drift bound. "),
    tx("The HLC_MAX_DRIFT_MS constant is the maximum offset by which an observed HLC may exceed the physical clock before the implementation rejects it. The reference implementations use 60,000ms (60 seconds). Without a drift bound, a malicious or buggy peer that sends an HLC value far in the future would force the local HLC to follow, and the local HLC would never recover. With a drift bound, observations beyond the bound are simply rejected, with the assumption that something has gone wrong upstream."),
  ]));

  out.push(p([
    bold("Counter overflow bumps logical time. "),
    tx("Unlike the Standard generator (which spins to the next millisecond on overflow), the HLC generator increments l by 1 and resets c to 0. This is correct for HLC semantics: the logical clock is allowed to run ahead of physical time as long as it is bounded by the drift parameter."),
  ]));

  out.push(h2("The Decoder"));

  out.push(p([
    tx("Decoders must validate inputs at every layer. The full validation chain for a decoded PQID:"),
  ]));

  out.push(numbered([tx("Verify length: exactly 41 bytes binary, 55 chars Base64URL, or 66 chars Crockford Base32.")]));
  out.push(numbered([tx("Decode the chosen text encoding into 41 bytes.")]));
  out.push(numbered([tx("Verify the variant byte (offset 6) is a known value (0x01 or 0x02 in v1; future versions may add more).")]));
  out.push(numbered([tx("Extract the 48-bit timestamp, 16-bit counter, and 256-bit random tail.")]));
  out.push(numbered([tx("Optionally validate the timestamp falls within reasonable bounds (e.g., not before service launch, not implausibly far in the future).")]));

  out.push(p([
    tx("Decoders SHOULD reject identifiers with unknown variant bytes. Decoders that accept unknown variants in the name of forward compatibility may silently misinterpret the timestamp, counter, or random fields, leading to incorrect ordering or duplicate detection failures."),
  ]));

  out.push(h2("Configuration Patterns"));

  out.push(p([
    tx("Library authors should expose three patterns of access, each appropriate for different consumers:"),
  ]));

  out.push(h3("Module-level convenience functions"));

  out.push(p([
    tx("The simplest API is a module-level function that returns a fresh PQID using a hidden default generator. This is what most callers want most of the time:"),
  ]));

  out.push(spacer());

  out.push(code(
    "import pqid\n" +
    "\n" +
    "id_bytes = pqid.new()                    # Standard variant, default generator\n" +
    "id_str   = pqid.encode_b64(id_bytes)     # 55-character Base64URL"
  ));

  out.push(h3("Explicit generator instances"));

  out.push(p([
    tx("Code that runs in many threads, or that wants to control state lifetime, can construct dedicated generator instances:"),
  ]));

  out.push(spacer());

  out.push(code(
    "from pqid import StandardGenerator\n" +
    "\n" +
    "gen_per_thread = threading.local()\n" +
    "def get_generator():\n" +
    "    g = getattr(gen_per_thread, 'g', None)\n" +
    "    if g is None:\n" +
    "        g = StandardGenerator()\n" +
    "        gen_per_thread.g = g\n" +
    "    return g\n" +
    "\n" +
    "def make_id():\n" +
    "    return get_generator().new()         # lock-free, per-thread"
  ));

  out.push(h3("Variant selection at the call site"));

  out.push(p([
    tx("For systems that mix variants, expose both options at the call site rather than relying on global configuration:"),
  ]));

  out.push(spacer());

  out.push(code(
    "id_for_event_log    = pqid.new_hlc(observe=incoming_hlc)\n" +
    "id_for_request      = pqid.new()         # Standard\n" +
    "id_for_audit_record = pqid.new_hlc()     # HLC, no peer to observe"
  ));

  out.push(p([
    tx("Avoid global \"variant mode\" toggles that change behavior across an entire process. They make local code harder to reason about and create bugs that are difficult to track down."),
  ]));

  return out;
}

function buildSecurity() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART VI: Security Analysis
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part VI: Security Analysis"));

  out.push(p([
    tx("This part lays out the threat model PQID is designed to handle, the cryptographic assumptions it makes, and the situations where it does not protect what users might assume it does. Many of the points here repeat themes from Parts III and IV in more rigorous form."),
  ]));

  out.push(h2("Threat Model"));

  out.push(p([
    tx("PQID provides three security properties:"),
  ]));

  out.push(numbered([
    bold("Collision resistance: "),
    tx("two PQIDs generated by independent parties using independent CSPRNGs are astronomically unlikely to collide. The 256-bit random field gives 128-bit post-quantum security against second-preimage attacks."),
  ]));

  out.push(numbered([
    bold("Generation-time disclosure: "),
    tx("the timestamp embedded in the PQID is recoverable, and is intended to be. Consumers can sort PQIDs by time without consulting external metadata."),
  ]));

  out.push(numbered([
    bold("Local monotonicity: "),
    tx("identifiers from a single generator are strictly increasing in lexicographic order, even in the face of clock regression."),
  ]));

  out.push(p([
    tx("PQID does NOT provide:"),
  ]));

  out.push(bullet([
    bold("Authenticity: "),
    tx("anyone with a CSPRNG can forge a valid-looking PQID. Use a signed envelope (PASETO [21], JWT [18], custom MAC) if you need to verify the producer."),
  ]));

  out.push(bullet([
    bold("Integrity: "),
    tx("PQID has no checksum, MAC, or hash. A bit-flipped PQID may decode to another valid PQID. If integrity matters, the PQID belongs inside a signed or HMAC'd [16] container that protects it."),
  ]));

  out.push(bullet([
    bold("Privacy: "),
    tx("the timestamp is recoverable. Don't use PQID where the time of generation must be hidden."),
  ]));

  out.push(bullet([
    bold("Linkability protection: "),
    tx("two PQIDs generated by the same generator within a short window may share a recoverable counter pattern that allows an observer to attribute them to the same source. The random initial counter and random step mitigate but do not eliminate this. If unlinkability across IDs matters, generate them from different processes or generator instances."),
  ]));

  out.push(h2("CSPRNG Requirements"));

  out.push(p([
    tx("The 32-byte random tail is what makes PQIDs unique. Generating it from anything other than a cryptographically-secure source destroys the format's security argument. Recommended sources by platform:"),
  ]));

  out.push(spacer());

  out.push(table(
    ["Platform", "Recommended CSPRNG", "Notes"],
    [
      ["Linux",         "getrandom(2)",                   "Blocks until kernel entropy pool initialized at boot."],
      ["macOS / *BSD",  "arc4random(3) or SecRandomCopyBytes", "Always available, never blocks."],
      ["Windows",       "BCryptGenRandom",                "Use BCRYPT_USE_SYSTEM_PREFERRED_RNG."],
      ["Node.js",       "crypto.randomFillSync",          "Wraps the platform CSPRNG."],
      ["Browser",       "crypto.getRandomValues",         "Web Crypto API; available in all current browsers."],
      ["Java",          "SecureRandom",                   "Use the default constructor; do NOT use 'NativePRNGNonBlocking' on Linux unless you understand the entropy implications."],
      ["Go",            "crypto/rand",                    "Wraps the platform CSPRNG."],
      ["Rust",          "getrandom crate",                "Wraps the platform CSPRNG."],
      ["Python",        "os.urandom or secrets module",   "Both wrap the platform CSPRNG."],
    ],
    [1500, 2400, 5460],
  ));

  out.push(p([
    tx("Implementations MUST NOT use Math.random, rand(), Mersenne Twister, or any non-cryptographic PRNG. Implementations MUST treat CSPRNG failure as a fatal error — generating a PQID with predictable randomness is worse than failing to generate one, because the predictable PQID may collide with other predictable PQIDs and cause silent data corruption."),
  ]));

  out.push(h2("The Quantum Argument, in Detail"));

  out.push(p([
    tx("Three quantum algorithms bear on the security of random identifiers."),
  ]));

  out.push(h3("Grover's algorithm (1996) [8]"));

  out.push(p([
    tx("Grover's algorithm searches an unstructured space of N elements in O(√N) operations. For an n-bit random field, this means finding a single specific value (a targeted second preimage) costs 2"),
    new TextRun({ text: "n/2", size: 22, superScript: true }),
    tx(" quantum operations instead of 2"),
    new TextRun({ text: "n", size: 22, superScript: true }),
    tx(" classical operations. For PQID's 256-bit random field, that's 2"),
    new TextRun({ text: "128", size: 22, superScript: true }),
    tx(" — astronomically out of reach for any plausible quantum computer."),
  ]));

  out.push(h3("Brassard-Hoyer-Tapp (1997) [9]"));

  out.push(p([
    tx("BHT extends Grover to find collisions: any two values in the space that share an output. For an n-bit space, BHT finds a collision in O(2"),
    new TextRun({ text: "n/3", size: 22, superScript: true }),
    tx(") operations. For PQID's 256-bit field, that's 2"),
    new TextRun({ text: "85", size: 22, superScript: true }),
    tx(" — large but not as comfortable as the 128-bit second-preimage bound. The relevant point is that for "),
    it("identifier"),
    tx(" use cases, second-preimage is the threat model that matters: an attacker wants to collide with a specific known PQID, not find any two PQIDs that collide. For audit-log integrity, second-preimage is the right bound, and 128 bits is the target."),
  ]));

  out.push(h3("Why not 384 or 512 bits?"));

  out.push(p([
    tx("Doubling the random field from 256 to 512 bits would give 256-bit post-quantum security, beyond any conceivable threat. The cost would be 32 extra bytes per identifier (PQID would grow from 41 to 73 bytes; Base64URL form would grow from 55 to 98 characters). At 128 bits of post-quantum security, PQIDs are already at the level the cryptographic community designs for; going further provides no practical security gain at significant byte cost. We chose 256 bits as the smallest field that achieves the target."),
  ]));

  out.push(h2("Side Channels"));

  out.push(p([
    tx("Two side channels in the PQID format deserve mention."),
  ]));

  out.push(h3("Timestamp leakage"));

  out.push(p([
    tx("Any attacker with access to a PQID can read its timestamp to within ~1ms. This is intended; the timestamp is what makes the format sortable. But it means PQIDs are unsuitable for use cases where the time of creation is itself sensitive (anti-fingerprinting tokens, anonymity-preserving identifiers). Use a separate identifier format derived from a random key for those cases."),
  ]));

  out.push(h3("Counter inference"));

  out.push(p([
    tx("An attacker who can observe many PQIDs from the same generator within a short window can, in principle, infer the generator's throughput by analyzing counter progression. The format mitigates this by starting the counter at a random offset within each new millisecond and incrementing by random steps in [1, 16]. The remaining signal is roughly equivalent to an adversary who measures generator throughput by externally counting requests; we consider this acceptable."),
  ]));

  out.push(p([
    tx("If counter-channel inference is a real concern (rare), the right defense is to use multiple generator instances with sharded inputs, so no single attacker-visible stream comes from a single generator."),
  ]));

  return out;
}

function buildDistributed() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART VII: Distributed Systems
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part VII: Distributed Systems Considerations"));

  out.push(p([
    tx("PQID was designed with multi-node generation in mind. This part covers the operational properties of running PQID at scale: collision math under multi-generator workloads, behavior under clock skew, the mechanics of HLC propagation, and patterns for horizontal scaling of HLC state."),
  ]));

  out.push(h2("Multi-Generator Collision Probability"));

  out.push(p([
    tx("With N independent generators each producing R IDs per second using independent CSPRNGs, the aggregate generation rate is N·R per second. The standard birthday bound says a 50% chance of any collision in a 256-bit random field arrives after about √(π/2) · 2"),
    new TextRun({ text: "128", size: 22, superScript: true }),
    tx(" ≈ 4.27 × 10"),
    new TextRun({ text: "38", size: 22, superScript: true }),
    tx(" generations, so the expected time to a collision is approximately √(π/2) · 2"),
    new TextRun({ text: "128", size: 22, superScript: true }),
    tx(" / (N · R) seconds. For concrete numbers:"),
  ]));

  out.push(spacer());

  out.push(table(
    ["Generators", "IDs/sec each", "Total IDs/sec", "Expected time to first collision"],
    [
      ["1",             "1,000,000",     "1,000,000",         "~1.4 × 10^25 years"],
      ["1,000",         "100,000",       "100,000,000",       "~1.4 × 10^23 years"],
      ["1,000,000",     "1,000",         "1,000,000,000",     "~1.4 × 10^22 years"],
      ["1,000,000,000", "1,000",         "1,000,000,000,000", "~1.4 × 10^19 years"],
    ],
    [2000, 2000, 2200, 3160],
  ));

  out.push(p([
    tx("These numbers far exceed the age of the universe (~1.4 × 10"),
    new TextRun({ text: "10", size: 22, superScript: true }),
    tx(" years). PQID's random field is large enough that collisions among independent generators are not a practical concern under any realistic load."),
  ]));

  out.push(callout(
    "What \"independent CSPRNGs\" means",
    "The collision argument assumes that every generator's CSPRNG produces statistically independent output. This is true for separate processes on separate machines using their respective OS CSPRNGs. It is NOT true if multiple generators share a single user-space PRNG state via fork(), or if multiple processes seed their PRNG from the same source at the same instant. fork() in Python especially deserves attention: child processes inherit the parent's os.urandom file descriptor cleanly (each call goes to the kernel afresh), but if you have any user-space RNG between you and os.urandom (e.g. random.SystemRandom mixed with random.Random), you may end up with shared state. Always confirm that each PQID generator backs onto a separate kernel-level CSPRNG instance.",
    "warning",
  ));

  out.push(h2("Clock Skew Behavior"));

  out.push(p([
    tx("PQID generators on different machines are subject to whatever clock skew exists between those machines. NTP [14] can synchronize machine clocks to roughly 1ms in a controlled data center and 10–100ms across the open internet; chronyd or PTP [15] can do better in tightly-controlled environments. PQID's behavior under skew depends on the variant."),
  ]));

  out.push(h3("Standard variant: skew shows up directly"));

  out.push(p([
    tx("Two Standard PQIDs generated on two different machines have timestamps that differ by approximately the clock skew between those machines. If machine A is 50ms ahead of machine B, an event A1 generated on A 30ms after event B1 on B will sort B1, A1 — correctly — but an event A2 generated on A 60ms before event B2 on B will sort A2, B2 — incorrectly, because A2's wall-clock timestamp is ahead of B2's even though B2 happened later."),
  ]));

  out.push(p([
    tx("For most use cases this is fine. Database indexes don't care about cross-node ordering accuracy; they care about each node's own writes being clustered. Logs aggregated from multiple machines are usually re-ordered by an external time-sorting layer that explicitly accounts for clock skew. If you need finer cross-node ordering than NTP delivers, use the HLC variant."),
  ]));

  out.push(h3("HLC variant: skew is bounded"));

  out.push(p([
    tx("HLC PQIDs are not subject to clock skew in the same way, but only when nodes exchange HLC values through messaging. The HLC update rule l_new = max(l_old, l_msg, pt) ensures that if node B receives a message from node A carrying A's HLC, B's subsequent HLCs will be at least as large as A's HLC — preserving the causal ordering A → B even if B's wall clock is behind A's."),
  ]));

  out.push(p([
    tx("The drift bound (60s in the reference implementations) limits how far ahead any node's HLC can run relative to its physical clock. If two nodes diverge in physical time by more than the drift bound, HLC observation between them will start failing — which is the correct behavior, because at that point the two clocks have lost any meaningful relationship and the system needs operator attention."),
  ]));

  out.push(h2("HLC Propagation"));

  out.push(p([
    tx("HLC provides causal ordering only when nodes exchange clock state in their messages. The minimum protocol-level requirement is:"),
  ]));

  out.push(numbered([tx("Every message carries the sender's most recent HLC reading.")]));
  out.push(numbered([tx("Every receiver feeds the message's HLC into its local HLC generator (via observe= in our reference implementations) before generating any new IDs.")]));
  out.push(numbered([tx("Receivers reject messages whose HLC exceeds the drift bound (60s default).")]));

  out.push(p([
    tx("In practice, this often looks like an extra 9-byte field on every message — six bytes of timestamp, one byte of variant, two bytes of counter — or even simpler, a full 41-byte PQID that doubles as a message identifier and an HLC reading. Many systems already carry an event ID with each message; promoting that to a PQID-HLC means HLC observation is automatic and zero-cost."),
  ]));

  out.push(h3("What happens without observation"));

  out.push(p([
    tx("HLC generators that never observe peers behave exactly like Standard generators with extra mutex overhead. The l field tracks the local wall clock, the c field stays near zero, and there is no causal information being preserved. This is the failure mode users most often run into when they reach for HLC: they label IDs as HLC-variant but never plumb observation through their messaging layer, so they pay HLC's cost without getting HLC's value."),
  ]));

  out.push(p([
    tx("If you're going to use the HLC variant, audit your message-passing code. Every place that crosses a node boundary should be observing HLCs from the inbound side and including local HLCs on the outbound side. If that audit reveals you can't do that practically, switch to the Standard variant."),
  ]));

  out.push(h2("Sharded HLC for Throughput"));

  out.push(p([
    tx("HLC requires a mutex around (l, c) updates, which caps single-instance throughput at the rate the mutex round-trip allows — roughly 1–2M operations per second on commodity hardware. For workloads above that rate, the standard pattern is to shard the HLC state across multiple instances per host:"),
  ]));

  out.push(spacer());

  out.push(code(
    "// One HLC generator per worker thread, with periodic merging.\n" +
    "thread_local hlc_generator local_hlc;\n" +
    "static     hlc_generator global_hlc;\n" +
    "static mutex             merge_lock;\n" +
    "\n" +
    "// Local generation: lock-free, fast.\n" +
    "Pqid local_id() { return local_hlc.new_id(); }\n" +
    "\n" +
    "// Periodic merge: combine the local HLC into the global one.\n" +
    "// Every N IDs, or every M ms, whichever comes first.\n" +
    "void merge_to_global() {\n" +
    "    auto local_view = local_hlc.snapshot();\n" +
    "    lock_guard lg(merge_lock);\n" +
    "    global_hlc.observe(local_view);\n" +
    "    local_hlc.observe(global_hlc.snapshot());\n" +
    "}"
  ));

  out.push(p([
    tx("Each per-thread HLC is its own causal domain; merging into a global HLC at periodic intervals (every 1ms, or every 10,000 IDs, depending on workload) brings the per-thread HLCs back into approximate sync. The cost is some loss of cross-thread causality precision — events that happened within a millisecond of each other on different threads may not be ordered correctly relative to each other. For workloads where that precision is unnecessary, this pattern unlocks linear scaling."),
  ]));

  out.push(h2("Mixing Variants in the Same Stream"));

  out.push(p([
    tx("PQID Standard and PQID HLC share the same wire format and the same lexicographic ordering, so the format technically permits mixing them in a single stream. We caution against doing so. The variant byte's purpose is to communicate the timestamp's semantics to consumers; if a consumer sees a stream of mixed variants, it cannot rely on any specific ordering interpretation."),
  ]));

  out.push(p([
    tx("If you need both wall-clock and HLC IDs in a single system, separate them by stream or by use case — for example, request IDs are Standard, event-log IDs are HLC. Do not interleave them in the same logical stream and expect cross-stream ordering to be meaningful."),
  ]));

  return out;
}

module.exports = { buildHow, buildSecurity, buildDistributed };
