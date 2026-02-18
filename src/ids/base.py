from collections import deque, defaultdict

from src.ids.cmds import get_host_ip

HOST_IP = get_host_ip()


def prune_queue(q: deque,
                now: float,
                window: float,
                offset: float) -> deque[float]:
    r = q.copy()
    lower = now - offset - window
    upper = now - offset
    while r and r[0] < lower:
        r.popleft()
    while r and r[-1] > upper:
        r.pop()
    return r


def prune_dict(d: defaultdict[str, deque[float]],
               now: float,
               window: float,
               offset: float) -> defaultdict[str, deque[float]]:
    r = d.copy()
    for k, v in r.items():
        r[k] = prune_queue(v, now, window, offset)
    return r


def update_thresholds(packets: defaultdict[str, deque],
                      now: float,
                      learning_phase: bool,
                      min_pps: float,
                      max_pps: float,
                      learning_k: float,
                      adaptive_k: float) -> tuple[bool, float]:
    pruned_packets = prune_dict(packets, now, 20, 0)

    avg_pps = sum(len(q) for q in pruned_packets.values()) / 20

    if learning_phase:
        threshold_pps = max(min_pps, min(max_pps, avg_pps * learning_k))
        learning_phase = False
    else:
        threshold_pps = max(min_pps, min(max_pps, avg_pps * adaptive_k))

    return learning_phase, threshold_pps


def get_pps(packets: defaultdict[str, deque], ip: str, now: float, window: float) -> tuple[float, float]:
    window_packets = prune_dict(packets, now, window, 0)
    avg_packets = prune_dict(packets, now, 20, window)

    current_pps = len(window_packets[ip]) / window
    avg_pps = (len(avg_packets[ip]) / 20)

    return current_pps, avg_pps
