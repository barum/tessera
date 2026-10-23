"""Prints the TesseraMark profile tables used in SPEC.md / RATIONALE.md (pure math, no keys)."""
import math

from tessera_mark import PROFILES

SEGMENTS = (2, 4, 6)
SESSIONS = (10**4, 10**6, 10**7)


def fmt_time(seconds: float) -> str:
    if seconds < 120:
        return f"{seconds:.0f} s"
    if seconds < 7200:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"


def binom_tail(n: int, k: int, p: float = 0.5) -> float:
    """P[X >= k] for X ~ Bin(n, p)."""
    return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k, n + 1))


def false_accept(profile, sessions: int, erasures: int = 0) -> float:
    """Garbage/forged word decodes to an *allocated* session: 2^(e-c) * N / 2^n."""
    return min(1.0, 2.0 ** (erasures - profile.check_bits) * sessions / 2.0**profile.code_bits)


def ml_false_accusation(n_obs: int, threshold: float, sessions: int) -> float:
    """Union bound: some innocent session agrees on >= threshold of n_obs random bits."""
    return min(1.0, sessions * binom_tail(n_obs, math.ceil(threshold * n_obs)))


def tardos_length(c: int, eps: float, n_users: int, kind: str) -> int:
    """Code length for c colluders, per-innocent error eps/N (union over N users).

    tardos: A = 100 (Tardos 2003/2008). symmetric: A = pi^2, provable for large c (Skoric,
    Katzenbeisser, Celik 2008). gaussian: A = pi^2/2 under the CLT approximation (same paper).
    bound: A = 2, the asymptotic capacity limit (Amiri-Tardos 2009; Huang-Moulin 2012).
    """
    k = {"tardos": 100.0, "symmetric": math.pi**2, "gaussian": math.pi**2 / 2, "bound": 2.0}[kind]
    return math.ceil(k * c * c * math.log(n_users / eps))


def main() -> None:
    print("| Profile | code n | check c | channel L | max erasures | " +
          " | ".join(f"clean @{s}s" for s in SEGMENTS) + " | robust 3xL @2s | robust 3xL @6s |")
    print("|---|---|---|---|---|" + "---|" * (len(SEGMENTS) + 2))
    for p in PROFILES.values():
        L = p.channel_bits
        row = [p.name, p.code_bits, p.check_bits, L, p.max_erasures]
        row += [fmt_time(L * s) for s in SEGMENTS] + [fmt_time(3 * L * 2), fmt_time(3 * L * 6)]
        print("| " + " | ".join(str(x) for x in row) + " |")
    print()
    print("| Profile | " + " | ".join(f"P(false accept) N={n:.0e}" for n in SESSIONS) +
          " | P(code collision) | ")
    print("|---|" + "---|" * (len(SESSIONS) + 1))
    for p in PROFILES.values():
        row = [p.name] + [f"{false_accept(p, n):.1e}" for n in SESSIONS] + ["0 (permutation)"]
        print("| " + " | ".join(row) + " |")
    print()
    print("Random-with-lookup (no permutation) birthday P(any collision) for comparison:")
    for p in PROFILES.values():
        cells = [f"N={n:.0e}: {min(1.0, n * n / 2.0 ** (p.code_bits + 1)):.1e}" for n in SESSIONS]
        print(f"  {p.name}: " + ", ".join(cells))
    print()
    print("ML (candidate-scoring) false accusation, N=1e6, threshold 0.80 agreement:")
    for n_obs in (48, 64, 96, 144):
        print(f"  {n_obs} segments: {ml_false_accusation(n_obs, 0.80, 10**6):.1e}")
    print()
    print("Collusion-resistant layer (bits = segments), eps = 1e-3, N = 1e6:")
    for c in (2, 3, 4, 8):
        cells = []
        for kind in ("tardos", "symmetric", "gaussian", "bound"):
            m = tardos_length(c, 1e-3, 10**6, kind)
            cells.append(f"{kind} {m} ({fmt_time(2 * m)} @2s, {fmt_time(6 * m)} @6s)")
        print(f"  c={c}: " + "; ".join(cells))


if __name__ == "__main__":
    main()
