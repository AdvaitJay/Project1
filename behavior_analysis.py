import math

def _path_metrics(path):
    if not path or len(path) < 2:
        return {
            "total_dist": 0.0, "net_disp": 0.0, "straightness": 1.0,
            "max_speed": 0.0, "avg_speed": 0.0, "speed_std": 0.0,
            "dir_changes_rate": 0.0, "jitter": 0.0, "samples": len(path or [])
        }
    speeds, dirs, accels = [], [], []
    total_dist = 0.0
    prev_v = None
    changes = 0
    for i in range(1, len(path)):
        x1,y1,t1 = path[i-1].get("x",0), path[i-1].get("y",0), path[i-1].get("t",0)
        x2,y2,t2 = path[i].get("x",0), path[i].get("y",0), path[i].get("t",t1+1)
        dt = max((t2 - t1)/1000.0, 1e-3)
        dx, dy = (x2-x1), (y2-y1)
        dist = math.hypot(dx, dy)
        v = dist/dt
        speeds.append(v)
        total_dist += dist
        theta = math.atan2(dy, dx) if dist > 0 else None
        dirs.append(theta)
        if prev_v is not None:
            accels.append(abs(v - prev_v)/dt)
        prev_v = v
    for i in range(2, len(dirs)):
        if dirs[i-1] is None or dirs[i] is None:
            continue
        dtheta = abs(dirs[i] - dirs[i-1])
        dtheta = min(dtheta, 2*math.pi - dtheta)
        if dtheta > math.pi/4:
            changes += 1
    duration_s = max((path[-1].get("t",0) - path[0].get("t",0))/1000.0, 1e-3)
    net_dx = (path[-1].get("x",0) - path[0].get("x",0))
    net_dy = (path[-1].get("y",0) - path[0].get("y",0))
    net_disp = math.hypot(net_dx, net_dy)
    straightness = (net_disp/total_dist) if total_dist > 0 else 1.0
    avg_speed = sum(speeds)/len(speeds) if speeds else 0.0
    max_speed = max(speeds) if speeds else 0.0
    variance = sum((v-avg_speed)**2 for v in speeds)/len(speeds) if speeds else 0.0
    speed_std = math.sqrt(variance)
    dir_changes_rate = changes/duration_s
    jitter = (sum(accels)/len(accels)) if accels else 0.0
    return {
        "total_dist": total_dist, "net_disp": net_disp, "straightness": straightness,
        "max_speed": max_speed, "avg_speed": avg_speed, "speed_std": speed_std,
        "dir_changes_rate": dir_changes_rate, "jitter": jitter, "samples": len(path)
    }

def analyze_behavior(data):
    clicks = int(data.get("clicks", 0))
    keys = int(data.get("keys", 0))
    moves = int(data.get("moves", 0))
    duration_ms = int(data.get("duration_ms", 1))
    path = data.get("path") or []
    pm = _path_metrics(path if isinstance(path, list) else [])
    cps = clicks / max(duration_ms / 1000, 1)
    kps = keys / max(duration_ms / 1000, 1)
    mps = moves / max(duration_ms / 1000, 1)
    tags = []
    if pm["max_speed"] > 2500 or pm["speed_std"] > 1200:
        tags.append("speed-spikes")
    if pm["dir_changes_rate"] > 6:
        tags.append("jerky-direction")
    if pm["straightness"] < 0.15 and pm["total_dist"] > 800:
        tags.append("low-straightness")
    if pm["jitter"] > 6000:
        tags.append("high-jitter")
    if cps > 6 or kps > 18 or mps > 120:
        tags.append("high-activity")
    score = sum(1 for f in ["high-activity","speed-spikes","jerky-direction","low-straightness","high-jitter"] if f in tags)
    severity = "info"
    if score >= 3:
        severity = "high"; 
        if "erratic" not in tags: tags.append("erratic")
    elif score == 2:
        severity = "medium"
    return severity, {"telemetry": {"clicks": clicks, "keys": keys, "moves": moves, "duration_ms": duration_ms, "path_samples": pm["samples"]},
                      "metrics": {"cps": cps, "kps": kps, "mps": mps, **pm},
                      "tags": tags}