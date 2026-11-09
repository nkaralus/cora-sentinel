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
def test_frames_more_than_one_and_a_half_windows_apart_are_coarse():
    s = RingStore()
    feed_steady(s, 8, step=0.25)                                           # fine: 0.25 s on a 1 s window
    feed_steady(s, 4, step=2.5, seq0=9, mono0=101.75 + 2.5)                # coarse: 2.5 s apart (> 1.5 x 1 s)
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



# ================================================================ jitter tolerance, mid-trip start
def test_a_heartbeat_arriving_at_1_99_s_on_a_1_s_window_is_still_coarse():
    s = RingStore()
    feed_steady(s, 8, step=1.99)
    segs = build_stall_segments(s.rings[7].samples, window_s=1.0)
    assert segs and all(seg.coarse for seg in segs)


def test_just_inside_one_and_a_half_windows_is_fine():
    s = RingStore()
    feed_steady(s, 12, step=1.5)
    segs = build_stall_segments(s.rings[7].samples, window_s=1.0)
    assert segs and not any(seg.coarse for seg in segs)


def test_a_hud_opened_mid_trip_shows_the_trip_but_marks_no_history():
    s = RingStore()
    s.feed(frame(1, 100.0, task(count=3)), 100.0)                          # first sight: active, count 3
    ring = s.rings[7]
    assert list(ring.marks) == [] and ring.pressure_active is True and samples(ring)[-1].pressure_count == 3
    s.feed(frame(2, 100.5, task(count=3)), 100.5)
    assert list(ring.marks) == [] and ring.pressure_active is True
    s.feed(frame(3, 101.0, task(count=4)), 101.0)
    assert list(ring.marks) == [Mark(101.0, "trip", "+1")]
    s.feed(frame(4, 101.5, task()), 101.5)                                  # the hub forgot the record: not active
    assert ring.pressure_active is False


# ================================================================ properties, over seeded random feeds
import random  # noqa: E402

THRESHOLDS = [ARMED_1S, ARMED_2S]
STATES = ["armed", "armed", "armed", "refused", "disabled", "unmonitored"]


def random_feed(seed, n=160):
    """A list of events: ("frame", frame, recv_time) or ("lost",). Jitter, gaps, lost links, epoch changes, exits,
    counter resets, a second cgroup that comes and goes."""
    rng = random.Random(seed)
    mono, seq, events = 100.0, 0, []
    some = {7: 0, 8: 0}
    state = {7: ("armed", 0), 8: ("unmonitored", 0)}
    count = {7: 0, 8: 0}
    for _ in range(n):
        mono += rng.choice([0.25, 0.25, 0.5, 0.25, 1.99, 2.0, 2.5, 5.0, 0.1])
        seq += 1
        if rng.random() < 0.04:
            events.append(("lost",))
        tasks = []
        for cid in (7, 8):
            if cid == 8 and rng.random() < 0.3:
                continue                                                  # missing from this frame
            if rng.random() < 0.06:
                state[cid] = (rng.choice(STATES), rng.randrange(2))
            if rng.random() < 0.03:
                some[cid] = 0                                             # a counter reset (a new cgroup)
            some[cid] += int(rng.random() * 400_000)
            if rng.random() < 0.1:
                count[cid] += rng.randrange(1, 3)
            st, ti = state[cid]
            tasks.append(task(cid, f"t{cid}", some=some[cid], full=some[cid] // 2, pids=0 if rng.random() < 0.05 else 1,
                              psi=rng.random() > 0.03, state=st, thr=THRESHOLDS[ti], count=count[cid] or None))
        events.append(("frame", frame(seq, mono, *tasks), mono + rng.random() * 0.01))
    return events


def play(store, events):
    for ev in events:
        if ev[0] == "lost":
            store.link_lost()
        else:
            store.feed(ev[1], ev[2])


def all_segments(store, window_s=1.0):
    return {cid: build_stall_segments(r.samples, window_s=window_s) for cid, r in store.rings.items()}


@pytest.mark.parametrize("seed", range(200))
def test_property_segments_never_overlap_and_never_cross_a_gap_or_an_epoch(seed):
    s = RingStore()
    play(s, random_feed(seed))
    for cid, ring in s.rings.items():
        segs = build_stall_segments(ring.samples, window_s=1.0)
        spans = sorted((seg.points[0][0], seg.points[-1][0]) for seg in segs)
        for seg in segs:
            ms = [m for m, _ in seg.points]
            assert ms == sorted(ms) and len(set(ms)) == len(ms)
        for (a0, a1), (b0, b1) in zip(spans, spans[1:]):
            assert a1 < b0, (seed, cid, (a0, a1), (b0, b1))               # P1: no overlap in time
        bounds = [p.mono for p in ring.samples if not isinstance(p, Sample)]
        for seg in segs:
            ms = [m for m, _ in seg.points]
            for b in bounds:
                assert all(m < b for m in ms) or all(m >= b for m in ms), (seed, cid, b, ms)   # P2


@pytest.mark.parametrize("seed", range(200))
def test_property_batch_feeding_gives_the_same_result_as_streaming(seed):
    events = random_feed(seed)
    stream = RingStore()
    for ev in events:                                                      # streamed, drawing after every frame
        play(stream, [ev])
        all_segments(stream)
    batch, run = RingStore(), []
    for ev in events + [("lost",)]:                                       # batched between link losses
        if ev[0] == "lost":
            batch.feed_many(run)
            run = []
            batch.link_lost()
        else:
            run.append((ev[1], ev[2]))
    batch._link_gap = stream._link_gap
    assert all_segments(batch) == all_segments(stream)
    assert {c: list(r.samples) for c, r in batch.rings.items()} == {c: list(r.samples) for c, r in stream.rings.items()}
    assert {c: list(r.marks) for c, r in batch.rings.items()} == {c: list(r.marks) for c, r in stream.rings.items()}


def test_property_the_sample_cap_holds_over_10000_frames():
    s = RingStore(window_s=10**9)
    for i in range(10_000):
        m = 100.0 + i * 0.1
        if i % 997 == 0:
            s.link_lost()
        s.feed(frame(i + 1, m, task(some=i * 1000, full=i * 500, thr=THRESHOLDS[(i // 1500) % 2])), m)
        assert len(s.rings[7].samples) <= rb.MAX_SAMPLES
    assert len(s.rings[7].samples) == rb.MAX_SAMPLES
