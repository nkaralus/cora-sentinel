"""cora_sentinel.ring_buffer: per-task history keyed by cgroup id; resets, gaps, epochs and bands, coarse spans, trip
and breaker marks, exited tasks; and the stall curves (undefined is empty, never 0). Pure: frames built by hand."""
import pytest

from cora_sentinel import ring_buffer as rb
from cora_sentinel.ring_buffer import Epoch, Mark, RingStore, Sample, build_stall_segments

ARMED_1S = {"kind": "some", "stall_us": 150000, "window_us": 1000000, "fraction": 0.15, "trigger": "some 150000 1000000"}
ARMED_2S = {"kind": "some", "stall_us": 300000, "window_us": 2000000, "fraction": 0.15, "trigger": "some 300000 2000000"}


def task(cid=7, name="game", some=0, full=0, pids=1, psi=True, state="armed", thr=ARMED_1S, count=None):
    t = {"name": name, "cgroup_id": cid, "pids": pids, "mem_bytes": 1 << 20, "psi_state": state,
         "psi_threshold": thr if state == "armed" else None}
    t["psi"] = {"some_total_us": some, "full_total_us": full, "some_avg10": 1.0, "full_avg10": 0.5} if psi else None
    if count is not None:
        t["pressure"] = {"active": True, "count": count, "some_avg10": 1.0, "full_avg10": 1.0}
    return t


def frame(seq, mono, *tasks):
    return {"seq": seq, "mono": mono, "tasks": list(tasks)}


def feed_steady(store, n, cid=7, name="game", per_s=100_000, step=0.25, seq0=1, mono0=100.0, **kw):
    """n frames `step` s apart, a task stalled per_s microseconds every second (10% at the default)."""
    for i in range(n):
        m = mono0 + i * step
        store.feed(frame(seq0 + i, m, task(cid, name, some=int((m - 100.0) * per_s), full=int((m - 100.0) * per_s / 2),
                                           **kw)), recv_time=m)


def samples(ring):
    return [p for p in ring.samples if isinstance(p, Sample)]


def pts(seg):
    return [m for m, _ in seg.points]


# ================================================================ the sample
def test_a_sample_keeps_the_raw_counters_and_the_tripwire_facts():
    s = RingStore()
    s.feed(frame(1, 100.0, task(some=5, full=3, count=2)), 100.0)
    assert samples(s.rings[7]) == [Sample(100.0, 5, 3, 1, "armed", ("some", 150000, 1000000), 2)]


def test_null_psi_is_none_never_zero():
    s = RingStore()
    s.feed(frame(1, 100.0, task(psi=False, state="refused")), 100.0)
    s.feed(frame(2, 101.0, task(psi=False, state="refused")), 101.0)
    got = samples(s.rings[7])
    assert all(x.some_total_us is None and x.full_total_us is None for x in got)
    assert build_stall_segments(s.rings[7].samples, window_s=1.0) == []    # nothing to draw, and no 0 line either


# ================================================================ keying and resets (unchanged rules)
def test_rings_are_keyed_by_cgroup_id_not_by_name():
    s = RingStore()
    s.feed(frame(1, 100.0, task(7, "game"), task(8, "game")), 100.0)
    s.feed(frame(2, 101.0, task(7, "game"), task(8, "game")), 101.0)
    assert sorted(s.rings) == [7, 8] and len(samples(s.rings[7])) == len(samples(s.rings[8])) == 2


def test_a_new_name_under_the_same_cgroup_id_starts_over():
    s = RingStore()
    feed_steady(s, 3)
    s.feed(frame(4, 101.0, task(7, "other", some=10**9)), 101.0)
    ring = s.rings[7]
    assert (ring.name, len(samples(ring)), ring.resets) == ("other", 1, 1)


@pytest.mark.parametrize("which", ["some", "full"])
def test_a_counter_that_goes_down_resets_the_ring(which):
    s = RingStore()
    feed_steady(s, 5)
    s.feed(frame(9, 102.0, task(some=5 if which == "some" else 500_000, full=5 if which == "full" else 300_000)), 102.0)
    assert s.rings[7].resets == 1 and [p.mono for p in samples(s.rings[7])] == [102.0]


@pytest.mark.parametrize("seq, mono", [(1, 200.0), (99, 50.0)])
def test_a_seq_or_mono_that_goes_back_resets_every_ring(seq, mono):
    s = RingStore()
    feed_steady(s, 4)
    s.feed(frame(seq, mono, task(7), task(9, "new")), mono)
    assert s.global_resets == 1 and sorted(s.rings) == [7, 9] and len(samples(s.rings[7])) == 1


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
def test_silence_longer_than_the_gap_limit_inserts_a_gap_and_a_lost_link_too():
    s = RingStore()
    s.feed(frame(1, 100.0, task()), 100.0)
    s.feed(frame(2, 104.5, task(some=10)), 104.5)                          # exactly 4.5 s: no gap
    s.feed(frame(3, 109.1, task(some=20)), 109.1)                          # 4.6 s: a gap
    s.link_lost()
    s.feed(frame(4, 110.0, task(some=30)), 110.0)
    assert [type(p).__name__ for p in s.rings[7].samples] == ["Sample", "Sample", "Gap", "Sample", "Gap", "Sample"]


def test_a_ring_never_starts_with_a_gap_or_an_epoch():
    s = RingStore()
    s.link_lost()
    s.feed(frame(1, 100.0, task()), 100.0)
    assert [type(p).__name__ for p in s.rings[7].samples] == ["Sample"]


# ================================================================ epochs and bands
def test_a_threshold_change_starts_a_new_epoch_and_splits_the_curve():
    s = RingStore()
    feed_steady(s, 9)                                                      # 100.00 .. 102.00, 1 s window
    feed_steady(s, 9, seq0=10, mono0=102.25, thr=ARMED_2S)                 # re-armed with a 2 s window
    ring = s.rings[7]
    eps = ring.epochs()
    assert [(e.mono, e.threshold) for e in eps] == [(100.0, ("some", 150000, 1000000)), (102.25, ("some", 300000, 2000000))]
    segs = build_stall_segments(ring.samples, window_s=1.0)
    assert [seg.threshold for seg in segs] == [("some", 150000, 1000000), ("some", 300000, 2000000)]
    assert max(pts(segs[0])) <= 102.0 and min(pts(segs[1])) >= 102.75     # nothing drawn across the boundary


def test_each_band_is_its_epochs_psi_state():
    s = RingStore()
    for i, state in enumerate(["armed", "armed", "armed", "refused", "refused", "refused", "disabled", "disabled",
                               "disabled", "unmonitored", "unmonitored", "unmonitored", "melting", "melting", "melting"]):
        m = 100.0 + i * 0.5
        s.feed(frame(i + 1, m, task(some=int((m - 100) * 100_000), state=state)), m)
    segs = build_stall_segments(s.rings[7].samples, window_s=1.0)
    assert [seg.band for seg in segs] == ["armed", "refused", "disabled", "unmonitored", "unknown"]
    assert [seg.threshold for seg in segs] == [("some", 150000, 1000000), None, None, None, None]
    assert sum(isinstance(p, Epoch) for p in s.rings[7].samples) == 4


# ================================================================ coarse spans
def test_frames_two_windows_apart_or_more_are_coarse():
    s = RingStore()
    feed_steady(s, 8, step=0.25)                                           # fine: 0.25 s on a 1 s window
    feed_steady(s, 4, step=2.5, seq0=9, mono0=101.75 + 2.5)                # coarse: 2.5 s apart (>= 2 x 1 s)
    segs = build_stall_segments(s.rings[7].samples, window_s=1.0)
    assert [seg.coarse for seg in segs] == [False, True]
    assert all(f == pytest.approx(0.10) for seg in segs for _, f in seg.points)
    assert min(pts(segs[1])) > max(pts(segs[0]))


def test_a_2s_heartbeat_on_a_1s_trigger_window_is_coarse_but_on_a_2s_window_it_is_not():
    one, two = RingStore(), RingStore()
    feed_steady(one, 6, step=2.0)
    feed_steady(two, 6, step=2.0, thr=ARMED_2S)
    assert {seg.coarse for seg in build_stall_segments(one.rings[7].samples, window_s=1.0)} == {True}
    assert {seg.coarse for seg in build_stall_segments(two.rings[7].samples, window_s=2.0)} == {False}


# ================================================================ marks
def test_a_rising_pressure_count_makes_a_trip_mark():
    s = RingStore()
    s.feed(frame(1, 100.0, task()), 100.0)                                 # no pressure record yet: baseline 0
    s.feed(frame(2, 101.0, task(count=1)), 101.0)
    s.feed(frame(3, 102.0, task(count=1)), 102.0)
    s.feed(frame(4, 103.0, task(count=4)), 103.0)
    assert list(s.rings[7].marks) == [Mark(101.0, "trip", "+1"), Mark(103.0, "trip", "+3")]


def test_a_count_seen_first_above_zero_is_history_and_a_falling_count_resets_the_baseline():
    s = RingStore()
    s.feed(frame(1, 100.0, task(count=5)), 100.0)                          # joined mid-way: no mark for those 5
    s.feed(frame(2, 101.0, task(count=2)), 101.0)                          # fell: new baseline, no mark
    s.feed(frame(3, 102.0, task(count=3)), 102.0)
    s.feed(frame(4, 103.0, task()), 103.0)                                 # record gone: baseline 0, no mark
    s.feed(frame(5, 104.0, task(count=1)), 104.0)
    assert list(s.rings[7].marks) == [Mark(102.0, "trip", "+1"), Mark(104.0, "trip", "+1")]


def test_trip_marks_are_per_cgroup():
    s = RingStore()
    s.feed(frame(1, 100.0, task(7, count=3), task(8, "game", count=0)), 100.0)
    s.feed(frame(2, 101.0, task(7, count=3), task(8, "game", count=1)), 101.0)
    assert list(s.rings[7].marks) == [] and list(s.rings[8].marks) == [Mark(101.0, "trip", "+1")]


def test_breaker_marks_sit_on_the_daemon_timeline():
    s = RingStore()
    s.feed(frame(1, 1000.0, task()), recv_time=50.0)
    assert s.mark_breaker(7, "sever", "sent", client_now=50.5)
    assert s.mark_breaker(7, "sever", "ok", client_now=50.6)
    assert not s.mark_breaker(99, "cap", "sent", client_now=50.7)          # no such task
    marks = list(s.rings[7].marks)
    assert [(m.kind, m.detail) for m in marks] == [("breaker", "sever:sent"), ("breaker", "sever:ok")]
    assert [m.mono for m in marks] == [1000.5, pytest.approx(1000.6)]


# ================================================================ exited tasks
def test_pids_zero_stops_the_curve_keeps_the_task_10s_then_drops_it_for_good():
    s = RingStore()
    feed_steady(s, 8)                                                      # 100.00 .. 101.75
    for i, m in enumerate([102.0, 102.25, 106.0, 112.0, 112.5, 113.0]):
        s.feed(frame(20 + i, m, task(some=int((m - 100) * 100_000), full=int((m - 100) * 50_000), pids=0)), m)
        if m <= 112.0:
            assert 7 in s.rings and s.rings[7].state == "exited"
    assert 7 not in s.rings                                                # 10.5 s after 102.0: dropped
    s.feed(frame(40, 113.5, task(pids=0)), 113.5)
    assert 7 not in s.rings                                                # a pids 0 report does not bring it back
    s.feed(frame(41, 114.0, task(some=10**9, pids=2)), 114.0)
    assert 7 in s.rings and s.rings[7].state == "live"                     # running again: a new ring


def test_no_curve_is_drawn_through_exited_samples():
    s = RingStore()
    feed_steady(s, 8)
    for i, m in enumerate([102.0, 102.25, 102.5]):
        s.feed(frame(20 + i, m, task(some=int((m - 100) * 100_000), full=int((m - 100) * 50_000), pids=0)), m)
    assert s.rings[7].resets == 0
    segs = build_stall_segments(s.rings[7].samples, window_s=1.0)
    assert segs and all(m <= 101.75 for seg in segs for m in pts(seg))


def test_a_task_missing_from_the_frames_is_exited_then_purged():
    s = RingStore()
    s.feed(frame(1, 100.0, task()), 100.0)
    s.feed(frame(2, 102.0), 102.0)
    assert s.rings[7].state == "exited"
    s.feed(frame(3, 112.0), 112.0)
    assert 7 in s.rings
    s.feed(frame(4, 112.5), 112.5)
    assert 7 not in s.rings


# ================================================================ capacity, the time axis, the curve's other rules
def test_a_ring_holds_120_s_and_at_most_2000_samples():
    s = RingStore()
    feed_steady(s, 100, step=2.0)
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


def test_points_without_half_a_window_behind_them_are_undefined_never_zero():
    s = RingStore()
    feed_steady(s, 8)                                                      # 100.00 .. 101.75
    segs = build_stall_segments(s.rings[7].samples, window_s=1.0)
    assert pts(segs[0])[0] == 100.5 and all(f > 0 for _, f in segs[0].points)


def test_a_gap_splits_the_curve_and_nothing_is_drawn_across_it():
    s = RingStore()
    monos = [100.0, 100.25, 100.5, 100.75, 101.0, 110.0, 110.25, 110.5, 110.75, 111.0]
    for i, m in enumerate(monos, 1):
        s.feed(frame(i, m, task(some=int((m - 100.0) * 100_000))), m)
    segs = build_stall_segments(s.rings[7].samples, window_s=1.0)
    assert [pts(seg) for seg in segs] == [[100.5, 100.75, 101.0], [110.5, 110.75, 111.0]]


def test_counter_anomalies_are_skipped_and_slight_overshoot_is_clamped():
    def smp(m, some):
        return Sample(m, some, 0, 1, "armed", ("some", 150000, 1000000), None)
    segs = build_stall_segments([smp(100.0, 0), smp(100.5, 508_000), smp(101.0, 3_000_000)], window_s=1.0)
    assert [seg.points for seg in segs] == [[(100.5, 1.0)]]


def test_points_older_than_the_span_are_left_out_and_which_is_checked():
    s = RingStore(window_s=1000)
    feed_steady(s, 200)
    now = s.right_edge(s.last_recv)
    segs = build_stall_segments(s.rings[7].samples, window_s=1.0, now_mono=now, span_s=5.0)
    assert segs and all(m >= now - 5.0 for seg in segs for m in pts(seg))
    with pytest.raises(ValueError):
        build_stall_segments([], 1.0, which="cpu")


def test_full_is_drawn_from_its_own_counter():
    s = RingStore()
    feed_steady(s, 12)
    full = build_stall_segments(s.rings[7].samples, window_s=1.0, which="full")
    assert full and all(f == pytest.approx(0.05) for seg in full for _, f in seg.points)


# ================================================================ moved here from cora-tray
def test_the_tray_meter_and_formatters_live_here_and_uiclient_still_exports_human_bytes():
    from cora_sentinel import uiclient
    assert uiclient.human_bytes is rb.human_bytes and rb.human_bytes(3 * 1024 ** 2) == "3.0 MiB"
    assert rb.fmt_pct(None) == "-" and rb.fmt_pct(12.345) == "12.35%" and set(rb.PALETTE) >= {"green", "red", "grey"}
    m = rb.StallMeter()
    m.feed({"mono": 100.0, "tasks": [task(some=0)]})
    m.feed({"mono": 110.0, "tasks": [task(some=1_000_000, full=500_000)]})
    assert m.fraction("game", 7) == (pytest.approx(0.1), pytest.approx(0.05))


def test_coarseness_is_judged_against_the_armed_tripwires_window_not_the_curves():
    s = RingStore()
    feed_steady(s, 6, step=2.0, thr=ARMED_2S)                               # 2 s frames, a 2 s trigger window
    segs = build_stall_segments(s.rings[7].samples, window_s=1.0)           # drawn on a 1 s curve window
    assert segs and {seg.coarse for seg in segs} == {False}                 # 2 s < 2 x 2 s: fine for this tripwire
    u = RingStore()
    feed_steady(u, 6, step=2.0, state="unmonitored")
    assert {seg.coarse for seg in build_stall_segments(u.rings[7].samples, window_s=1.0)} == {True}   # no tripwire: window_s


def test_a_threshold_is_only_kept_for_an_armed_tripwire():
    s = RingStore()
    for i in range(6):
        m = 100.0 + i * 0.25
        t = task(some=int((m - 100) * 100_000), state="refused")
        t["psi_threshold"] = dict(ARMED_1S)                                 # a feed that should not have sent it
        s.feed(frame(i + 1, m, t), m)
    assert {x.threshold for x in samples(s.rings[7])} == {None}
    assert {seg.threshold for seg in build_stall_segments(s.rings[7].samples, window_s=1.0)} == {None}
