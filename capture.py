"""Packet capture engine — entity learning + speed modification.

Architecture:
  - Sniff thread: always-on read-only capture for entity learning (broad filter)
  - Intercept handles: per-port packet interception with tight kernel filters
  - Both run simultaneously — sniff never stops when intercept starts
  - Port changes and mode switches only affect intercept handles

Communication with UI via event queue:
  ('log', message_string)
  ('error', message_string)
  ('entity', (actor_id, name, strategy))
"""

import json
import os
import queue
import threading
import time
from datetime import datetime

import pydivert
from pydivert import Param, Flag

from protocol import (
    find_all_skill_ids, find_attack_speed_offset,
    extract_entity_key, encode_varint_fixed,
    StreamReassembler,
)


def _tune_handle(w):
    """Maximize WinDivert kernel queue buffers."""
    try:
        w.set_param(Param.QUEUE_LEN, 16384)
        w.set_param(Param.QUEUE_SIZE, 33554432)  # 32 MB
        w.set_param(Param.QUEUE_TIME, 16000)     # 16 seconds (max)
    except Exception:
        pass


# ── WinDivert filters ─────────────────────────────────────────

_SNIFF_FILTER = (
    "tcp and tcp.DstPort > 1024 and tcp.SrcPort > 1024 and ("
    "(inbound and ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1) or "
    "loopback"
    ")"
)


_PAYLOAD_FILTER = "and tcp.PayloadLength >= 40"


def _build_single_port_filter(port: int, is_loopback: bool) -> str:
    """Build a WinDivert filter for a single port — one handle per port."""
    if is_loopback:
        return (f"loopback and tcp and !impostor "
                f"and tcp.SrcPort == {port} {_PAYLOAD_FILTER}")
    else:
        return (f"inbound and tcp and tcp.SrcPort == {port} "
                f"and ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1 "
                f"{_PAYLOAD_FILTER}")


def _build_intercept_filter(ports: set, is_loopback: bool) -> str:
    """Build a broad intercept filter (fallback when no ports detected)."""
    if is_loopback:
        if ports:
            clauses = ' or '.join(f'tcp.SrcPort == {p}' for p in sorted(ports))
            return (f"loopback and tcp and !impostor and ({clauses}) "
                    f"{_PAYLOAD_FILTER}")
        return (f"loopback and tcp and !impostor "
                f"and tcp.DstPort > 1024 and tcp.SrcPort > 1024 {_PAYLOAD_FILTER}")
    else:
        if ports:
            clauses = ' or '.join(f'tcp.SrcPort == {p}' for p in sorted(ports))
            return (f"inbound and tcp and ({clauses}) "
                    f"and ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1 "
                    f"{_PAYLOAD_FILTER}")
        return (f"inbound and tcp and tcp.DstPort > 1024 and tcp.SrcPort > 1024 "
                f"and ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1 "
                f"")


# ── Async log writer ──────────────────────────────────────────

class _LogWriter:
    """Non-blocking JSONL file writer for packet logs."""

    def __init__(self, filepath: str):
        self._queue: queue.Queue = queue.Queue()
        self._file = open(filepath, 'w', encoding='utf-8')
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def put(self, entry: dict):
        try:
            self._queue.put_nowait(entry)
        except queue.Full:
            pass

    def _drain(self):
        while not self._stop.is_set():
            try:
                entry = self._queue.get(timeout=0.5)
                self._file.write(json.dumps(entry) + '\n')
                self._file.flush()
            except queue.Empty:
                continue
            except Exception:
                pass

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        while not self._queue.empty():
            try:
                entry = self._queue.get_nowait()
                self._file.write(json.dumps(entry) + '\n')
            except Exception:
                break
        try:
            self._file.flush()
            self._file.close()
        except Exception:
            pass


# ── Capture engine ─────────────────────────────────────────────

class CaptureEngine:
    """Single-threaded packet capture with entity learning and speed modification.

    Usage:
        engine = CaptureEngine(skill_data, entity_tracker, port_tracker, event_queue)
        engine.start()                          # begins in sniff mode
        engine.set_intercepting(True, lookup)    # switch to intercept
        engine.set_intercepting(False)           # back to sniff
        engine.stop()
    """

    def __init__(self, skill_data, entity_tracker, port_tracker, event_queue):
        self._skill_data = skill_data
        self._entity_tracker = entity_tracker
        self._port_tracker = port_tracker
        self._events = event_queue

        self._sniff_thread = None
        self._intercept_thread = None
        self._stop = threading.Event()
        self._reopen_intercept = threading.Event()
        self._handles: list = []
        self._handle_lock = threading.Lock()

        # Mode: sniff (read-only) or intercept (modify + send)
        self._intercept = False

        # Speed config: skill_id -> (encoded_bytes, encoded_len, speed_pct, break_packet)
        self._speed_lookup: dict = {}

        # Target IDs for scanning (set by UI when starting intercept)
        self._target_ids: set = skill_data.all_ids
        self._first_bytes: set = skill_data.first_bytes

        # Skill event callback (for weave engine integration)
        self._on_skill_event = None

        # Stream reassembler for entity detection (single-threaded, no lock needed)
        self._reassembler = StreamReassembler()

        # Stats
        self.modified_count = 0

        # Packet logging
        self._log_writer: _LogWriter | None = None

        # Processing time stats (intercept only)
        self._pkt_times: list[float] = []
        self._pkt_stats_lock = threading.Lock()
        self._last_stats_time = 0.0

    def start(self):
        """Start capture — sniff thread starts immediately, intercept on demand."""
        self._stop.clear()
        self._sniff_thread = threading.Thread(target=self._run_sniff, daemon=True)
        self._sniff_thread.start()

    def stop(self):
        """Stop all capture threads and clean up."""
        self._stop.set()
        self._reopen_intercept.set()
        self._close_intercept_handles()
        if self._sniff_thread:
            self._sniff_thread.join(timeout=5)
            self._sniff_thread = None
        if self._intercept_thread:
            self._intercept_thread.join(timeout=5)
            self._intercept_thread = None
        self._stop_logging()

    def set_intercepting(self, enabled: bool, speed_lookup: dict = None,
                         target_ids: set = None, first_bytes: set = None):
        """Start or stop intercept handles (sniff keeps running independently)."""
        if speed_lookup is not None:
            self._speed_lookup = speed_lookup
        if target_ids is not None:
            self._target_ids = target_ids
            self._first_bytes = first_bytes or set()

        was_intercept = self._intercept
        self._intercept = enabled

        if enabled and not was_intercept:
            # Start intercept thread
            self._reopen_intercept.clear()
            self._intercept_thread = threading.Thread(
                target=self._run_intercept_loop, daemon=True)
            self._intercept_thread.start()
        elif not enabled and was_intercept:
            # Stop intercept thread
            self._reopen_intercept.set()
            self._close_intercept_handles()
            if self._intercept_thread:
                self._intercept_thread.join(timeout=5)
                self._intercept_thread = None

    def update_speed_lookup(self, lookup: dict, target_ids: set = None,
                            first_bytes: set = None):
        """Hot-reload speed config while capture is running."""
        self._speed_lookup = lookup
        if target_ids is not None:
            self._target_ids = target_ids
            self._first_bytes = first_bytes or set()

    def set_skill_callback(self, callback):
        """Register a callback for skill ACT/FB events (for weave engine).
        callback(skill_name, skill_id, pkt_type, tick)"""
        self._on_skill_event = callback

    def on_ports_changed(self, ports: set):
        """Called by port tracker when game ports change."""
        self._emit('log', f"Ports: {sorted(ports)}")
        if self._intercept:
            self._reopen_intercept.set()
            self._close_intercept_handles()

    def start_logging(self, logs_dir: str):
        """Start packet JSONL logging."""
        self._stop_logging()
        try:
            os.makedirs(logs_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(logs_dir, f"packets_{ts}.jsonl")
            self._log_writer = _LogWriter(path)
            self._emit('log', f"Logging to packets_{ts}.jsonl")
        except Exception as e:
            self._emit('log', f"Log error: {e}")

    def set_logging(self, enabled: bool, logs_dir: str = None):
        """Enable or disable packet JSONL logging."""
        if enabled:
            if self._log_writer:
                return
            if logs_dir is None:
                return
            self.start_logging(logs_dir)
        else:
            self._stop_logging()

    def _stop_logging(self):
        if self._log_writer:
            self._log_writer.close()
            self._log_writer = None

    # ── Internal ──────────────────────────────────────────────

    def _emit(self, event_type: str, data=None):
        try:
            self._events.put_nowait((event_type, data))
        except queue.Full:
            pass

    def _log_packet(self, entry: dict):
        if self._log_writer:
            entry['timestamp'] = datetime.now().isoformat()
            self._log_writer.put(entry)

    def _close_intercept_handles(self):
        """Close only intercept handles (sniff handle is separate)."""
        with self._handle_lock:
            for h in self._handles:
                try:
                    h.close()
                except Exception:
                    pass
            self._handles.clear()

    def _run_sniff(self):
        """Always-on sniff thread for entity learning. Runs until stop."""
        time.sleep(0.5)  # let port tracker do initial scan

        while not self._stop.is_set():
            try:
                handle = pydivert.WinDivert(_SNIFF_FILTER, flags=Flag.SNIFF)
                handle.open()
            except PermissionError:
                self._emit('error', 'Run as Administrator')
                return
            except Exception as e:
                self._emit('error', str(e))
                self._stop.wait(2)
                continue

            self._emit('log', "Sniffing (entity learning)")

            try:
                while not self._stop.is_set():
                    try:
                        packet = handle.recv()
                    except Exception:
                        break
                    self._process_packet(packet, handle, False)
            finally:
                try:
                    handle.close()
                except Exception:
                    pass

    def _run_intercept_loop(self):
        """Intercept thread — reopens handles on port changes, runs until stopped."""
        while not self._stop.is_set() and self._intercept:
            self._reopen_intercept.clear()
            self._run_intercept()


    def _run_intercept(self):
        """One handle per port, one thread per handle — independent kernel queues."""
        ports = self._port_tracker.get_ports()
        is_loopback = self._port_tracker.get_loopback_mode()
        mode = 'loopback' if is_loopback else 'direct'

        # Build per-port filters (or one broad filter if no ports yet)
        if ports:
            filters = []
            for port in sorted(ports):
                filters.append(_build_single_port_filter(port, is_loopback))
        else:
            filters = [_build_intercept_filter(set(), is_loopback)]

        # Open handles
        handles = []
        try:
            for filt in filters:
                h = pydivert.WinDivert(filt)
                h.open()
                _tune_handle(h)
                handles.append(h)
        except PermissionError:
            for h in handles:
                try: h.close()
                except Exception: pass
            self._emit('error', 'Run as Administrator')
            return
        except Exception as e:
            for h in handles:
                try: h.close()
                except Exception: pass
            self._emit('error', str(e))
            self._stop.wait(2)
            return

        with self._handle_lock:
            self._handles = list(handles)

        self._emit('log',
            f"Intercepting ({mode}) {len(handles)} handles, ports {sorted(ports) if ports else 'broad'}")

        # One worker thread per handle
        workers = []
        for h in handles:
            t = threading.Thread(target=self._intercept_worker, args=(h,), daemon=True)
            t.start()
            workers.append(t)

        # Wait for stop, mode change, or port change
        while not self._stop.is_set() and not self._reopen_intercept.is_set() and self._intercept:
            self._stop.wait(timeout=0.5)

        # Close intercept handles (unblocks recv in workers)
        with self._handle_lock:
            self._handles.clear()
        for h in handles:
            try:
                h.close()
            except Exception:
                pass

        for t in workers:
            t.join(timeout=3)

    def _intercept_worker(self, handle):
        """Worker thread for a single WinDivert handle."""
        while not self._stop.is_set() and not self._reopen_intercept.is_set():
            try:
                packet = handle.recv()
            except Exception:
                break
            t0 = time.perf_counter_ns()
            self._process_packet(packet, handle, True)
            elapsed_us = (time.perf_counter_ns() - t0) / 1000
            with self._pkt_stats_lock:
                self._pkt_times.append(elapsed_us)
            now = time.monotonic()
            if now - self._last_stats_time >= 10.0:
                self._report_pkt_stats(now)

    def _report_pkt_stats(self, now):
        with self._pkt_stats_lock:
            times = self._pkt_times
            self._pkt_times = []
        self._last_stats_time = now
        if not times:
            return
        times.sort()
        cnt = len(times)
        avg = sum(times) / cnt
        p50 = times[cnt // 2]
        p99 = times[int(cnt * 0.99)]
        mx = times[-1]
        self._emit('log',
            f"[Perf] {cnt} pkts/10s avg:{avg:.0f}us p50:{p50:.0f}us p99:{p99:.0f}us max:{mx:.0f}us")

    def _process_packet(self, packet, handle, is_intercept: bool):
        """Process a single captured packet.

        Unified flow: parse → scan → modify → send → learn entities.
        Entity learning and skill scanning both happen on every packet.
        """
        raw = packet.raw
        raw_len = len(raw)

        if raw_len < 40:
            if is_intercept:
                try: handle.send(packet)
                except Exception: pass
            return

        # Parse IP/TCP headers
        ip_hdr_len = (raw[0] & 0x0F) * 4
        tcp_hdr_len = (raw[ip_hdr_len + 12] >> 4) * 4
        payload_offset = ip_hdr_len + tcp_hdr_len

        if payload_offset >= raw_len:
            if is_intercept:
                try: handle.send(packet)
                except Exception: pass
            return

        payload = raw[payload_offset:]
        plen = raw_len - payload_offset

        # ── Skill scan — find all matches, pick ours ──
        skill_id = 0
        skill_offset = -1
        prefix_ok = False
        skip_modify = False
        matched_char = None

        if plen >= 40:
            target_ids = self._target_ids
            first_bytes = self._first_bytes

            all_hits = find_all_skill_ids(payload, target_ids, first_bytes)

            # Pick the right match: prefer our entity, fall back to first
            if all_hits:
                use_entity_filter = (is_intercept
                                     and self._entity_tracker.is_configured
                                     and self._entity_tracker.has_any_keys())

                best = None
                matched_char = None
                for sid, soff, spfx in all_hits:
                    ek = extract_entity_key(payload, soff)
                    if use_entity_filter:
                        if ek is not None and self._entity_tracker.is_mine(ek):
                            matched_char = self._entity_tracker.get_name_for_key(ek)
                            best = (sid, soff, spfx, ek)
                            break
                    else:
                        best = (sid, soff, spfx, ek)
                        break

                if best:
                    skill_id, skill_offset, prefix_ok, entity_key = best
                elif not use_entity_filter and all_hits:
                    h = all_hits[0]
                    skill_id, skill_offset, prefix_ok = h
                    entity_key = extract_entity_key(payload, skill_offset)
                else:
                    skip_modify = True
                    # Still set skill_id for logging from first hit
                    h = all_hits[0]
                    skill_id, skill_offset, prefix_ok = h
                    entity_key = extract_entity_key(payload, skill_offset)

        if skill_id:
            pkt_type = payload[skill_offset + 5] if skill_offset + 5 < plen else -1
            skill_name = self._skill_data.id_to_name.get(skill_id, f"ID:{skill_id}")

        # ── Modify + learn speed (if skill found and not filtered) ──
        if skill_id and not skip_modify:
            # Find speed offset from verified ACT
            speed_result = None
            if prefix_ok and pkt_type == 0x02:
                speed_result = find_attack_speed_offset(payload, skill_offset)

            # Speed modification
            log_entry = {
                'skill_name': skill_name, 'skill_id': skill_id,
                'pkt_type': pkt_type, 'prefix_ok': prefix_ok,
            }
            if entity_key is not None:
                log_entry['entity_key'] = entity_key
            if matched_char:
                log_entry['character'] = matched_char

            if is_intercept and self._intercept:
                if prefix_ok and pkt_type == 0x02 and speed_result:
                    self._modify_act(packet, speed_result, skill_id, payload_offset,
                                     log_entry, matched_char)
                elif prefix_ok and pkt_type != 0x02:
                    log_entry['action'] = 'non_act'
                else:
                    log_entry['action'] = 'no_speed_offset'

            # Disk log
            log_entry['offset'] = skill_offset
            log_entry['plen'] = plen
            self._log_packet(log_entry)

        # ── Send packet ──
        if is_intercept:
            try: handle.send(packet)
            except Exception: pass

        # ── Post-send: skill callback ──
        # Only fire from the active path: intercept when intercepting, sniff when not
        if skill_id and not skip_modify and is_intercept == self._intercept:
            tick = payload[skill_offset + 4] if skill_offset + 4 < plen else 0
            if self._on_skill_event and pkt_type in (0x02, 0x03):
                try:
                    self._on_skill_event(skill_name, skill_id, pkt_type, tick)
                except Exception:
                    pass

        # Entity learning — sniff mode only (intercept handles are filtered tight)
        if not is_intercept and plen > 3:
            self._learn_entities(payload)

    def _modify_act(self, packet, speed_result, skill_id, payload_offset,
                    log_entry, char_name=None):
        """Modify attack speed in a verified ACT packet."""
        speed_info = self._speed_lookup.get(skill_id)
        if not speed_info:
            log_entry['action'] = 'no_speed_config'
            return

        skill_name = log_entry.get('skill_name', '?')
        tag = f"[{char_name}] " if char_name else ""
        spd_off, spd_len, spd_val = speed_result
        encoded_speed, encoded_len, speed_pct, allow_break = speed_info
        raw_off = payload_offset + spd_off

        if spd_val < 10000:
            log_entry['action'] = 'below_threshold'
            return

        if allow_break:
            packet.raw[raw_off:raw_off + spd_len] = b'\xff' * spd_len
            self.modified_count += 1
            log_entry['action'] = 'modified_break'
            log_entry['original_speed'] = spd_val
            self._emit('log', f"{tag}ACT {skill_name} spd:{spd_val} -> break")
            return

        # Match byte length
        if encoded_len != spd_len:
            encoded_speed = encode_varint_fixed(speed_pct * 100, spd_len)
            encoded_len = len(encoded_speed)

        if encoded_len == spd_len:
            packet.raw[raw_off:raw_off + spd_len] = encoded_speed
            self.modified_count += 1
            log_entry['action'] = 'modified'
            log_entry['original_speed'] = spd_val
            log_entry['new_speed'] = speed_pct * 100
            self._emit('log', f"{tag}ACT {skill_name} spd:{spd_val} -> {speed_pct * 100}")
        else:
            max_val = (1 << (7 * spd_len)) - 1
            capped = encode_varint_fixed(min(speed_pct * 100, max_val), spd_len)
            packet.raw[raw_off:raw_off + spd_len] = capped
            self.modified_count += 1
            log_entry['action'] = 'modified_capped'
            log_entry['original_speed'] = spd_val
            self._emit('log', f"{tag}ACT {skill_name} spd:{spd_val} -> capped")


    def _learn_entities(self, payload):
        """Feed payload to stream reassembler and process entity bindings."""
        bindings = self._reassembler.feed(payload)
        for actor_id, name, strategy, msg_hex in bindings:
            accepted = self._entity_tracker.on_binding(
                actor_id, name, strategy=strategy, msg_hex=msg_hex)
            if accepted:
                self._emit('entity', (actor_id, name, strategy))
                self._emit('log', f"[Entity] Bound: {name} -> key {actor_id} ({strategy})")
