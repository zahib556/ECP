"""Фаззер на стандартной библиотеке: мутационный, с обратной связью по исходам и сторожем зависаний.

Запуск (из корня проекта, в активном venv):
    python fuzz/run_fuzz.py --list
    python fuzz/run_fuzz.py --target asn1_parse --time 60
    python fuzz/run_fuzz.py --target all --time 60 --seed 1

Почему не только Atheris: он не поддерживается на Windows; этот запуск работает везде. Atheris-вариант
для Linux/WSL - fuzz/fuzz_atheris.py (те же цели).

Как работает: из начального корпуса (seeds) выводятся мутанты (биты, байты, вставки, удаления, дубли,
фрагменты словаря, склейки). Вход, давший новый исход (тип исключения + место в коде), попадает в корпус.
Падение = исключение вне списка допустимых, нарушенное свойство (AssertionError) или зависание
(по умолчанию > 2 с). Входы падений сохраняются в fuzz/crashes/ (каталог в .gitignore).
Код возврата: 0 - падений нет, 1 - есть падения, 3 - зависание.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from targets import TARGETS  # noqa: E402

CRASH_DIR = Path(__file__).resolve().parent / "crashes"
MAX_LEN = 4096
INTERESTING = [0x00, 0x01, 0x7F, 0x80, 0x81, 0x82, 0x84, 0xFF, 0x20, 0x0A, 0x2E, 0x30, 0x31]


def mutate(rng: random.Random, data: bytes, corpus: list, words: list) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.choice((1, 1, 2, 3, 5))):
        op = rng.randrange(9)
        n = len(buf)
        if op == 0 and n:
            buf[rng.randrange(n)] ^= 1 << rng.randrange(8)
        elif op == 1 and n:
            buf[rng.randrange(n)] = rng.randrange(256)
        elif op == 2:
            pos = rng.randrange(n + 1)
            buf[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        elif op == 3 and n > 1:
            a = rng.randrange(n)
            del buf[a:a + rng.randint(1, min(16, n - a))]
        elif op == 4 and n:
            a = rng.randrange(n)
            chunk = buf[a:a + rng.randint(1, 32)]
            pos = rng.randrange(len(buf) + 1)
            buf[pos:pos] = chunk * rng.randint(1, 4)
        elif op == 5 and words:
            pos = rng.randrange(n + 1)
            buf[pos:pos] = rng.choice(words)
        elif op == 6 and n:
            buf[rng.randrange(n)] = rng.choice(INTERESTING)
        elif op == 7 and len(corpus) > 1:
            other = rng.choice(corpus)
            buf = buf[:rng.randrange(n + 1)] + other[rng.randrange(len(other) + 1):]
        elif op == 8 and n:
            a = rng.randrange(n)
            buf[a:a + 1] = b""  # укорочение
    return bytes(buf[:MAX_LEN])


def _site(exc: BaseException) -> tuple:
    tb = traceback.extract_tb(exc.__traceback__)
    last = tb[-1] if tb else None
    return (type(exc).__name__, os.path.basename(last.filename) if last else "", last.lineno if last else 0)


class Watchdog(threading.Thread):
    def __init__(self, timeout: float):
        super().__init__(daemon=True)
        self.timeout, self.started, self.current, self.name_ = timeout, None, b"", ""

    def run(self) -> None:
        while True:
            time.sleep(0.1)
            t0 = self.started
            if t0 is not None and time.monotonic() - t0 > self.timeout:
                CRASH_DIR.mkdir(exist_ok=True)
                path = CRASH_DIR / f"hang-{self.name_}-{hashlib.sha1(self.current).hexdigest()[:10]}.bin"
                path.write_bytes(self.current)
                print(f"\n!!! ЗАВИСАНИЕ (> {self.timeout} с) в цели {self.name_}; вход сохранён: {path}", flush=True)
                print(f"    вход (первые 80 байт): {self.current[:80]!r}", flush=True)
                os._exit(3)


def run_target(name: str, seconds: float, seed: int, wd: Watchdog) -> dict:
    target = TARGETS[name]
    rng = random.Random(f"{seed}:{name}")
    corpus = list(target.seeds) or [b""]
    words = list(target.tokens)
    seen: set = set()
    crashes: dict = {}
    execs = 0
    wd.name_ = name
    t_end = time.monotonic() + seconds
    t_start = time.monotonic()
    next_report = t_start + 10
    for seed_input in corpus[:]:  # сначала сами seeds - они обязаны проходить
        wd.current, wd.started = seed_input, time.monotonic()
        try:
            target.func(seed_input)
        except target.allowed:
            pass
        except Exception as e:  # noqa: BLE001
            print(f"  внимание: начальный вход цели {name} вызывает {type(e).__name__}: {e}")
        wd.started = None
        execs += 1
    while time.monotonic() < t_end:
        base = rng.choice(corpus)
        data = mutate(rng, base, corpus, words)
        wd.current, wd.started = data, time.monotonic()
        try:
            target.func(data)
            outcome = ("ok",)
        except target.allowed as e:
            outcome = _site(e)
        except Exception as e:  # noqa: BLE001
            wd.started = None
            key = _site(e)
            if key not in crashes:
                CRASH_DIR.mkdir(exist_ok=True)
                digest = hashlib.sha1(data).hexdigest()[:10]
                (CRASH_DIR / f"crash-{name}-{digest}.bin").write_bytes(data)
                trace = "".join(traceback.format_exception(type(e), e, e.__traceback__))
                (CRASH_DIR / f"crash-{name}-{digest}.txt").write_text(trace, encoding="utf-8")
                crashes[key] = (data, trace)
                print(f"\n!!! ПАДЕНИЕ #{len(crashes)} в цели {name}: {key[0]} ({key[1]}:{key[2]}): {e}")
                print(f"    вход ({len(data)} байт): {data[:80]!r}  -> crashes/crash-{name}-{digest}.bin", flush=True)
            outcome = ("crash",) + key
        wd.started = None
        execs += 1
        if outcome not in seen:
            seen.add(outcome)
            if len(data) <= MAX_LEN and outcome[0] != "crash":
                corpus.append(data)
        if time.monotonic() >= next_report:
            next_report += 10
            print(f"  [{name}] {time.monotonic() - t_start:5.0f} c: входов {execs}, исходов {len(seen)}, "
                  f"корпус {len(corpus)}, падений {len(crashes)}", flush=True)
    elapsed = time.monotonic() - t_start
    return {"target": name, "execs": execs, "seconds": elapsed, "outcomes": len(seen), "corpus": len(corpus),
            "crashes": crashes}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="all", help="имя цели или all")
    ap.add_argument("--time", type=float, default=60.0, help="секунд на каждую цель (по умолчанию 60)")
    ap.add_argument("--seed", type=int, default=1, help="начальное значение генератора (воспроизводимость)")
    ap.add_argument("--hang", type=float, default=2.0, help="порог зависания одного входа, с")
    ap.add_argument("--list", action="store_true", help="показать цели")
    args = ap.parse_args(argv)
    if args.list:
        print("\n".join(TARGETS))
        return 0
    names = list(TARGETS) if args.target == "all" else [args.target]
    for n in names:
        if n not in TARGETS:
            print(f"неизвестная цель {n}; доступны: {', '.join(TARGETS)}")
            return 2
    try:  # ограничение памяти: бесконечный цикл с ростом списка не должен «съесть» компьютер
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (3 << 30, 3 << 30))
    except (ImportError, ValueError, OSError):
        pass
    wd = Watchdog(args.hang)
    wd.start()
    print(f"Фаззинг: python {sys.version.split()[0]}, seed={args.seed}, {args.time:.0f} с на цель, цели: {', '.join(names)}")
    results = [run_target(n, args.time, args.seed, wd) for n in names]
    print("\n=== Итог ===")
    print(f"{'цель':<16}{'входов':>10}{'вход/с':>9}{'исходов':>9}{'падений':>9}")
    total = bad = 0
    for r in results:
        total += r["execs"]
        bad += len(r["crashes"])
        print(f"{r['target']:<16}{r['execs']:>10}{r['execs'] / max(r['seconds'], 1e-9):>9.0f}{r['outcomes']:>9}{len(r['crashes']):>9}")
    print(f"{'ВСЕГО':<16}{total:>10}{'':>9}{'':>9}{bad:>9}")
    if bad:
        print(f"Входы падений сохранены в {CRASH_DIR}")
    else:
        print("Падений и зависаний не обнаружено.")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
