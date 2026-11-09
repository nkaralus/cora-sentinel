"""cora_sentinel.ring_buffer: per-task history keyed by cgroup id, its reset and gap rules, and the stall curves drawn
from it (undefined is empty, never 0). Pure: no sockets, no Qt, frames built by hand."""
import pytest

from cora_sentinel import ring_buffer as rb
from cora_sentinel.ring_buffer import Gap, RingStore, Sample, build_stall_segments


def task(cid=7, name="game", some=0, full=0, mem=1 << 20, psi=True):
    t = {"name": name, "cgroup_id": cid, "mem_bytes": mem}
    t["psi"] = {"some_total_us": some, "full_total_us": full, "some_avg10": 1.0, "full_avg10": 0.5} if psi else None
    return t


def frame(seq, mono, *tasks):
    return {"seq": seq, "mono": mono, "tasks": list(tasks)}


def feed_steady(store, n, cid=7, name="game", per_s=100_000, step=2.0, seq0=1, mono0=100.0):
    """n frames, 2 s apart, a task stalled per_s microseconds every second (10% at the default)."""
    for i in range(n):
        m = mono0 + i * step
        store.feed(frame(seq0 + i, m, task(cid, name, some=int((m - mono0) * per_s), full=int((m - mono0) * per_s / 2))),
                   recv_time=m)


def samples(ring):
    return [p for p in ring.samples if isinstance(p, Sample)]


# ================================================================ keying and resets
def test_rings_are_keyed_by_cgroup_id_not_by_name():
    s = RingStore()
    s.feed(frame(1, 100.0, task(7, "game"), task(8, "game")), 100.0)       # two cgroups, one name
    assert sorted(s.rings) == [7, 8]
    s.feed(frame(2, 102.0, task(7, "game"), task(8, "game")), 102.0)
    assert len(samples(s.rings[7])) == len(samples(s.rings[8])) == 2


def test_a_new_name_under_the_same_cgroup_id_starts_over():
    s = RingStore()
    feed_steady(s, 3)
    s.feed(frame(4, 106.0, task(7, "other", some=10**9)), 106.0)
    ring = s.rings[7]
    assert (ring.name, len(samples(ring)), ring.resets) == ("other", 1, 1)


@pytest.mark.parametrize("which", ["some", "full"])
def test_a_counter_that_goes_down_resets_the_ring(which):
    s = RingStore()
    feed_steady(s, 3)                                   # counters reach 400000 / 200000
    s.feed(frame(4, 106.0, task(7, some=5 if which == "some" else 500_000, full=5 if which == "full" else 300_000)), 106.0)
    ring = s.rings[7]
    assert ring.resets == 1 and [p.mono for p in samples(ring)] == [106.0]


def test_a_seq_that_goes_back_resets_every_ring():
    s = RingStore()
    feed_steady(s, 4)
    s.feed(frame(1, 200.0, task(7), task(9, "new")), 200.0)                # a restarted daemon starts at seq 1
    assert s.global_resets == 1 and sorted(s.rings) == [7, 9] and len(samples(s.rings[7])) == 1


def test_a_mono_that_goes_back_resets_every_ring():
    s = RingStore()
    feed_steady(s, 4)
    s.feed(frame(99, 50.0, task(7)), 50.0)
    assert s.global_resets == 1 and len(samples(s.rings[7])) == 1 and s.last_mono == 50.0


def test_the_same_seq_twice_is_ignored_and_malformed_frames_too():
    s = RingStore()
    assert s.feed(frame(1, 100.0, task()), 100.0)
    assert not s.feed(frame(1, 101.0, task(some=999)), 101.0)
    for bad in (None, [], {"seq": "1", "mono": 1.0}, {"seq": 2}, {"seq": 2, "mono": "x"}, {"seq": True, "mono": 1.0}):
        assert not s.feed(bad, 102.0)
    assert len(samples(s.rings[7])) == 1 and s.global_resets == 0


@pytest.mark.parametrize("cid", [None, "7", True, 7.0])
def test_a_task_without_an_integer_cgroup_id_gets_no_history(cid):
    s = RingStore()
    s.feed(frame(1, 100.0, task(cid)), 100.0)
    assert s.rings == {}


# ================================================================ gaps
def test_silence_longer_than_the_gap_limit_inserts_a_gap():
    s = RingStore()
    s.feed(frame(1, 100.0, task()), 100.0)
    s.feed(frame(2, 104.5, task(some=10)), 104.5)                          # exactly 4.5 s: no gap
    s.feed(frame(3, 109.1, task(some=20)), 109.1)                          # 4.6 s: a gap
    kinds = [type(p).__name__ for p in s.rings[7].samples]
    assert kinds == ["Sample", "Sample", "Gap", "Sample"] and s.rings[7].samples[2] == Gap(109.1)


def test_a_lost_link_inserts_a_gap_before_the_next_sample_only():
    s = RingStore()
    s.feed(frame(1, 100.0, task()), 100.0)
    s.link_lost()
    s.feed(frame(2, 102.0, task(some=10)), 102.0)
    s.feed(frame(3, 104.0, task(some=20)), 104.0)
    assert [type(p).__name__ for p in s.rings[7].samples] == ["Sample", "Gap", "Sample", "Sample"]


def test_a_gap_is_never_the_first_thing_in_a_ring():
    s = RingStore()
    s.link_lost()
    s.feed(frame(1, 100.0, task()), 100.0)
    assert [type(p).__name__ for p in s.rings[7].samples] == ["Sample"]


# ================================================================ exited tasks, capacity, the time axis
def test_a_vanished_task_is_kept_as_exited_for_ten_seconds_then_purged():
    s = RingStore()
    s.feed(frame(1, 100.0, task()), 100.0)
    s.feed(frame(2, 102.0), 102.0)
    assert s.rings[7].state == "exited" and s.rings[7].exited_at == 102.0
    s.feed(frame(3, 112.0), 112.0)                                         # 10 s exactly: still kept
    assert 7 in s.rings
    s.feed(frame(4, 112.5), 112.5)
    assert 7 not in s.rings


def test_a_task_that_comes_back_within_the_hold_is_live_again():
    s = RingStore()
    s.feed(frame(1, 100.0, task()), 100.0)
    s.feed(frame(2, 102.0), 102.0)
    s.feed(frame(3, 104.0, task(some=10)), 104.0)
    assert s.rings[7].state == "live" and len(samples(s.rings[7])) == 2


def test_a_ring_holds_120_s_and_at_most_2000_samples():
    s = RingStore()
    feed_steady(s, 100)                                                    # 198 s of frames, 2 s apart
    ring = s.rings[7]
    assert ring.samples[0].mono >= ring.samples[-1].mono - rb.WINDOW_S and len(ring.samples) == 61
    s2 = RingStore(window_s=10_000)
    feed_steady(s2, 2100, step=0.5)
    assert len(s2.rings[7].samples) == rb.MAX_SAMPLES


def test_the_right_edge_moves_with_client_time_when_the_feed_is_silent():
    s = RingStore()
    assert s.right_edge(5.0) is None
    s.feed(frame(1, 1000.0, task()), recv_time=50.0)
    assert s.right_edge(50.0) == 1000.0 and s.right_edge(57.5) == 1007.5 and s.right_edge(40.0) == 1000.0


# ================================================================ the curve
def test_a_steady_stall_is_its_exact_fraction():
    s = RingStore()
    feed_steady(s, 20, per_s=100_000)                                      # 10% some, 5% full
    segs = build_stall_segments(s.rings[7].samples, window_s=10.0, now_mono=s.right_edge(138.0))
    assert len(segs) == 1 and all(f == pytest.approx(0.10) for _, f in segs[0])
    full = build_stall_segments(s.rings[7].samples, window_s=10.0, which="full")
    assert all(f == pytest.approx(0.05) for _, f in full[0])


def test_points_without_half_a_window_behind_them_are_undefined_never_zero():
    s = RingStore()
    feed_steady(s, 6)                                                      # 100..110
    segs = build_stall_segments(s.rings[7].samples, window_s=10.0)
    xs = [m for m, _ in segs[0]]
    assert xs == [106.0, 108.0, 110.0]                                     # 100, 102, 104 have < 5 s behind them
    assert all(f > 0 for _, f in segs[0])


def test_a_gap_splits_the_curve_and_nothing_is_drawn_across_it():
    s = RingStore()
    monos = [100.0, 102.0, 104.0, 106.0, 108.0, 110.0, 120.0, 122.0, 124.0, 126.0, 128.0, 130.0]   # a 10 s hole
    for i, m in enumerate(monos, 1):
        s.feed(frame(i, m, task(some=int((m - 100.0) * 100_000))), m)    # counters keep climbing through the hole
    assert sum(isinstance(p, Gap) for p in s.rings[7].samples) == 1
    segs = build_stall_segments(s.rings[7].samples, window_s=10.0)
    assert [[m for m, _ in seg] for seg in segs] == [[106.0, 108.0, 110.0], [126.0, 128.0, 130.0]]
    assert all(f == pytest.approx(0.10) for seg in segs for _, f in seg)  # no line, and no 0, across 110 -> 126


def test_a_sample_without_psi_ends_the_segment():
    pts = [Sample(100.0 + 2 * i, i * 200_000, i * 100_000, None, None, None) for i in range(12)]
    pts[5] = Sample(110.0, None, None, None, None, None)
    segs = build_stall_segments(pts, window_s=6.0)
    assert [[m for m, _ in seg] for seg in segs] == [[104.0, 106.0, 108.0], [116.0, 118.0, 120.0, 122.0]]  # run 2 starts at 112


def test_counter_anomalies_are_skipped_and_slight_overshoot_is_clamped():
    pts = [Sample(100.0, 0, 0, None, None, None), Sample(106.0, 6_100_000, 0, None, None, None),   # 1.0167: clamp
           Sample(112.0, 30_000_000, 0, None, None, None)]                                          # 3.98: skip
    segs = build_stall_segments(pts, window_s=6.0)
    assert segs == [[(106.0, 1.0)]]


def test_points_older_than_the_span_are_left_out():
    s = RingStore(window_s=1000)
    feed_steady(s, 100)
    now = s.right_edge(s.last_recv)
    segs = build_stall_segments(s.rings[7].samples, window_s=10.0, now_mono=now, span_s=20.0)
    assert segs and all(m >= now - 20.0 for seg in segs for m, _ in seg)


def test_which_must_be_some_or_full():
    with pytest.raises(ValueError):
        build_stall_segments([], 10.0, which="cpu")


# ================================================================ moved here from cora-tray
def test_the_tray_meter_and_formatters_live_here_and_uiclient_still_exports_human_bytes():
    from cora_sentinel import uiclient
    assert uiclient.human_bytes is rb.human_bytes and rb.human_bytes(3 * 1024 ** 2) == "3.0 MiB"
    assert rb.fmt_pct(None) == "-" and rb.fmt_pct(12.345) == "12.35%" and set(rb.PALETTE) >= {"green", "red", "grey"}
    m = rb.StallMeter()
    m.feed({"mono": 100.0, "tasks": [task(some=0)]})
    m.feed({"mono": 110.0, "tasks": [task(some=1_000_000, full=500_000)]})
    assert m.fraction("game", 7) == (pytest.approx(0.1), pytest.approx(0.05))
