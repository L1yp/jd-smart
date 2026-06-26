#!/usr/bin/env python3
"""JD 小京鱼 四接口端到端联调测试器（获取家庭 / 设备 / 状态 / 控制）。

直接复用 HA 集成的**生产签名与解析代码**（custom_components/jd_smart/api.py）：
构造 `JdSmartClient(session=None)` 拿它的同步方法 now_ts / authorization / _common_params /
_headers / build_*_body —— 这些**全不碰 aiohttp**；只把 `_post` 的 aiohttp 传输换成标准库 urllib。
解析直接调 `api.parse_houses_gw / parse_devices_gw / parse_stream_model / control_kind /
parse_snapshot`。所以"测的就是 HA 实际跑的代码"——签名、body、解析三者与运行时零偏差，
唯一不同的只有 HTTP 传输层（urllib 替 aiohttp，因为本机没装 aiohttp）。

覆盖（**四条全部走 gw.smart.jd.com 统一网关**，同一套 HmacSHA1 签名、同一个小京鱼 tgt）：
  ① 获取家庭  POST gw /s/service/getHousesAndRooms                    body {}
  ② 获取设备  POST gw /c/service/devmanager/v2/getDevicesAndCategory  body {"houseId"}
  ③ 获取状态  ├ 物模型 POST gw /c/service/devmanager/v1/getDeviceDetails   body {device_id,json_data{feed_id,houseId}}
              └ 快照   POST gw /c/service/integration/v1/getDeviceSnapshot_v1  body {"json":{feed_id,...}}
  ④ 控制设备  POST gw /c/service/integration/v1/controlDevice_v1      body {"json":"<inner>"}
注：③快照/④控制这两条 integration/v1 接口若发往 api.smart.jd.com，用小京鱼 tgt 恒 -4「登录已
过期」（那套要另一 App 的登录态/pin）；gw.smart.jd.com 转发同一接口、当前 tgt 即 status=0——故全走 gw。

③ 物模型那步会把每条流按 `control_kind` 映射成 **HA 实体类型**（switch/select/number/只读
sensor·binary_sensor），直接预览"HA 设备详情界面会生成哪些实体"——排查"只有 Power 开关 /
缺实体 / 值不对 / 控件类型错"最有用，对照这张表即可定位问题出在哪个接口。

凭据读 jd_smart_secrets.json（同 gw_test.py / color_test.py，已 .gitignore）。device_id 只放
query、不参与签名、服务端不严格校验：优先 secrets.device_id，否则 md5(android_id)，可用
--device-id 覆盖（UUID 也行）。tgt 必须是小京鱼 App 的、且新鲜。

用法:
  python jd_e2e_test.py                       # 全流程：家庭→设备→每台(物模型+快照)，控制仅 dry-run 预览
  python jd_e2e_test.py --feed 576...755       # 只详测这一台（仍先发现家庭/设备）
  python jd_e2e_test.py --house 1388207        # 只测这个家庭
  python jd_e2e_test.py --control 576...755:Power:1   # 真实下发一条控制（会改变设备状态！）
  python jd_e2e_test.py --dry-run              # 全程只签名打印不发送（离线验签 / 脚本自检）
  python jd_e2e_test.py --raw                  # 响应原样打印，不美化/不解析
  python jd_e2e_test.py --device-id b0b5...    # 覆盖 device_id（query 用，不签名）
"""
import argparse
import gzip
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
_PKG = os.path.join(HERE, "custom_components", "jd_smart")
sys.path.insert(0, _PKG)  # 让 `import api`/`const`/`color_api` 命中集成代码（api.py 脚本模式已支持）

import api  # noqa: E402  复用生产签名/解析；JdSmartClient(session=None) 不触发 aiohttp
import const  # noqa: E402

_SECRETS = os.path.join(HERE, "jd_smart_secrets.json")
_REQUIRED = ("seg1", "key", "tgt")


# ────────────────────────────── 凭据 ──────────────────────────────
def load_secrets(path):
    if not os.path.exists(path):
        sys.exit(f"[!] 缺 {os.path.basename(path)}：拷 jd_smart_secrets.example.json 填真实值。")
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    miss = [k for k in _REQUIRED if not (cfg.get(k) or "").strip()]
    if miss:
        sys.exit(f"[!] {os.path.basename(path)} 缺字段: {', '.join(miss)}（见 *.example.json）")
    return cfg


def resolve_device_id(cfg, override=None):
    """device_id 只放 query、不参与签名：override > secrets.device_id > md5(android_id) > 占位。"""
    if override:
        return override.strip()
    did = (cfg.get("device_id") or "").strip()
    if did:
        return did
    aid = (cfg.get("android_id") or "").strip()
    if aid:
        return hashlib.md5(aid.encode("utf-8")).hexdigest()
    return "00000000-0000-0000-0000-000000000000"


def make_client(cfg):
    """构造生产 JdSmartClient（session=None：本测试器只用其同步签名/body 方法，不发包）。"""
    return api.JdSmartClient(
        None,
        seg1=cfg["seg1"],
        key=cfg["key"],
        tgt=cfg["tgt"],
        hard_platform=cfg.get("hard_platform") or const.DEFAULT_HARD_PLATFORM,
        app_version=cfg.get("app_version") or const.DEFAULT_APP_VERSION,
        plat_version=cfg.get("plat_version") or const.DEFAULT_PLAT_VERSION,
        channel=cfg.get("channel") or const.DEFAULT_CHANNEL,
        plat=cfg.get("plat") or const.DEFAULT_PLAT,
    )


def compact(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


# ────────────────────────────── 传输（urllib 替 aiohttp，签名/body 全复用生产）──────────────────────────────
class Transport:
    """复刻 JdSmartClient._post 的 url/params/headers 装配，但用 urllib 同步发包。"""

    def __init__(self, client, device_id, *, timeout=20, dry_run=False, raw=False):
        self.c = client
        self.device_id = device_id
        self.timeout = timeout
        self.dry_run = dry_run
        self.raw = raw

    def call(self, label, path, body, *, base=None):
        """签名→打印(隐藏 tgt)→发送→解析。返回解析后的 JSON（dry-run / 失败返回 None）。"""
        ts = self.c.now_ts()
        url = (base or const.API_BASE) + path + "?" + urllib.parse.urlencode(
            self.c._common_params(self.device_id))
        headers = self.c._headers(body, ts)  # 含生产签名的 authorization + tgt
        print(f"\n>>> {label}")
        print(f"    URL  : {url}")
        print(f"    Auth : {headers['authorization']}")
        print(f"    tgt  : <{len(self.c.tgt)} chars, hidden>")
        print(f"    body : {body}")
        if self.dry_run:
            print("    (--dry-run：不发送)")
            return None
        status, text = self._send(url, body, headers)
        return self._show(label, status, text)

    def _send(self, url, body, headers):
        req = urllib.request.Request(url, data=body.encode("utf-8"), method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return resp.getcode(), raw.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                if (e.headers.get("Content-Encoding") or "") == "gzip":
                    raw = gzip.decompress(raw)
            except (OSError, EOFError):
                pass
            return e.code, raw.decode("utf-8", "replace")
        except urllib.error.URLError as e:
            return None, f"URLError: {e.reason}"

    def _show(self, label, status, text):
        print(f"    HTTP : {status}")
        if self.raw:
            print("    RAW  : " + text[:4000])
            try:
                return json.loads(text)
            except ValueError:
                return None
        try:
            obj = json.loads(text)
        except ValueError:
            print("    BODY : " + text[:2000])
            return None
        return obj


# ────────────────────────────── 物模型 → HA 实体类型预览 ──────────────────────────────
def ha_entity_kind(stream_id, m):
    """把一条物模型流映射成 HA 会建的实体类型（与各 platform 文件的判定对齐）。

    可控（control_kind 非 None）→ switch/select/number；
    只读 → 0/1 枚举或 BINARY_STREAMS 内 → binary_sensor，其余 → sensor。
    """
    kind = api.control_kind(m)
    if kind:
        return kind
    opts = m.get("options") or {}
    if stream_id in const.BINARY_STREAMS or set(opts) == {"0", "1"}:
        return "binary_sensor"
    return "sensor"


def _detail_str(m):
    """流的取值范围/枚举的人类可读摘要。"""
    opts = m.get("options")
    if opts:
        items = list(opts.items())
        head = ", ".join(f"{k}:{v}" for k, v in items[:4])
        more = f" …(+{len(items) - 4})" if len(items) > 4 else ""
        return f"{{{head}{more}}}"
    lo, hi, st = m.get("min"), m.get("max"), m.get("step")
    if lo is not None or hi is not None:
        unit = m.get("unit") or ""
        step = f"/step{st}" if st not in (None, "") else ""
        return f"{lo}..{hi}{unit}{step}"
    return "-"


def print_model_table(model):
    """打印物模型 → HA 实体路由表，并汇总各类型数量。"""
    if not model:
        print("    （物模型为空——HA 会回退 card_meta，通常只剩 Power 开关）")
        return {}
    print(f"    {'stream_id':<18}{'name':<12}{'type':<5}{'enum':<5}{'detail':<26}{'current':<10}-> HA")
    print("    " + "-" * 90)
    tally = {}
    for sid, m in model.items():
        ent = ha_entity_kind(sid, m)
        tally[ent] = tally.get(ent, 0) + 1
        st = m.get("stream_type")
        st_s = {0: "0可控", 1: "1只读"}.get(st, str(st))
        name = (m.get("name") or "")[:11]
        cur = m.get("current")
        cur_s = ("" if cur is None else str(cur))[:9]
        print(f"    {sid:<18}{name:<12}{st_s:<5}{str(m.get('is_enum')):<5}"
              f"{_detail_str(m):<26}{cur_s:<10}-> {ent}")
    print("    " + "-" * 90)
    summary = "  ".join(f"{k}={v}" for k, v in sorted(tally.items()))
    ctrl = sum(v for k, v in tally.items() if k in ("switch", "select", "number"))
    print(f"    汇总：{summary}    （可控实体 switch+select+number = {ctrl}）")
    return tally


# ────────────────────────────── 四步 ──────────────────────────────
def step_houses(tx):
    raw = tx.call("① 获取家庭 getHousesAndRooms  body={}", const.GW_HOUSES_PATH, "{}",
                  base=const.GW_API_BASE)
    if raw is None:
        return []
    houses = api.parse_houses_gw(raw)
    print(f"    解析：{len(houses)} 个家庭")
    for h in houses:
        rooms = ", ".join(f"{n}={i}" for n, i in (h.get("rooms") or {}).items())
        print(f"      house_id={h['house_id']}  name={h['house_name']}  rooms[{rooms}]")
    return houses


def step_devices(tx, house):
    hid = house["house_id"]
    raw = tx.call(f"② 获取设备 getDevicesAndCategory  houseId={hid}", const.GW_DEVICES_PATH,
                  compact({"houseId": str(hid)}), base=const.GW_API_BASE)
    if raw is None:
        return []
    devs = api.parse_devices_gw(raw, house_id=hid, room_map=house.get("rooms"),
                                requester_device_id=tx.device_id)
    print(f"    解析：{len(devs)} 台设备")
    for d in devs:
        print(f"      feed_id={d['feed_id']}  name={d.get('name')}  room={d.get('room')}"
              f"(room_id={d.get('room_id')})  hw={d.get('hw_device_id')}  streams={d.get('streams')}")
    return devs


def step_status(tx, dev):
    """③ 获取状态 = 物模型(getDeviceDetails) + 快照(getDeviceSnapshot)。"""
    feed_id = dev["feed_id"]
    house_id = dev.get("house_id")
    name = dev.get("name", feed_id)
    print(f"\n========== 设备「{name}」 feed_id={feed_id} house_id={house_id} ==========")

    # 3a 物模型（决定生成哪些实体——HA 设备详情界面的核心）
    raw = tx.call("③a 物模型 getDeviceDetails", const.GW_DETAILS_PATH,
                  api.JdSmartClient.build_device_details_body(feed_id, house_id),
                  base=const.GW_API_BASE)
    model = {}
    if raw is not None:
        model = api.parse_stream_model(raw)
        # 与 coordinator 一致：用 card_meta 的枚举标签补 value_des 为空的可控枚举流
        api_enrich(model, dev)
        if not model:
            print("    [!] 物模型解析为空：检查 houseId 是否正确、tgt 是否过期。")
            print("        原始片段：" + compact(raw)[:300])
        print_model_table(model)

    # 3b 实时快照（决定 sensor 当前值 / 实体状态）——走 gw 统一网关（api.smart 域用此 tgt 恒 -4）
    raw_s = tx.call("③b 快照 getDeviceSnapshot（gw）", const.SNAPSHOT_PATH,
                    api.JdSmartClient.build_body(feed_id), base=const.GW_API_BASE)
    if raw_s is not None:
        snap = api.parse_snapshot(raw_s)
        ok = snap.get("ok")
        print(f"    解析：ok={ok}  api_status={snap.get('api_status')}  error={snap.get('error')}"
              f"  device_status={snap.get('device_status')}")
        if not ok:
            print("    [!] 快照业务失败：tgt 过期最常见，或 feed_id 不被接受。")
        streams = snap.get("streams") or {}
        print(f"    streams({len(streams)})：" + compact(streams)[:600])
    return model


def api_enrich(model, dev):
    """复刻 coordinator._enrich_options_from_card_meta（脚本里独立一份，避免 import HA 依赖）。"""
    cmeta = dev.get("card_meta") or {}
    for sid, entry in model.items():
        cm = cmeta.get(sid) or {}
        if not entry.get("options") and cm.get("options"):
            entry["options"] = cm["options"]
        if not entry.get("unit") and cm.get("unit"):
            entry["unit"] = cm["unit"]


def step_control(tx, dev_by_feed, spec, model_by_feed):
    """④ 控制设备。spec='FEED:STREAM:VALUE'；无 spec 则对首台可控流 dry-run 预览（不发）。"""
    print("\n========== ④ 控制设备 controlDevice ==========")
    if spec:
        parts = spec.split(":", 2)
        if len(parts) != 3:
            print("    [!] --control 格式应为 FEED:STREAM:VALUE")
            return
        feed_s, stream_id, value = parts
        feed_id = _match_feed(feed_s, dev_by_feed)
        if feed_id is None:
            print(f"    [!] 未在已发现设备里找到 feed_id≈{feed_s}")
            return
        dev = dev_by_feed[feed_id]
        body = api.JdSmartClient.build_control_body(feed_id, [{"stream_id": stream_id,
                                                               "current_value": value}])
        print(f"    目标：{dev.get('name')}  feed_id={feed_id}  写 {stream_id}={value}"
              f"  —— 这会真实改变设备状态！")
        raw = tx.call("④ controlDevice（真实下发，gw）", const.CONTROL_PATH, body,
                      base=const.GW_API_BASE)
        if raw is not None:
            parsed = api.parse_snapshot(raw)
            print(f"    解析：ok={parsed.get('ok')}  control_ret={parsed.get('control_ret')}"
                  f"  error={parsed.get('error')}")
            print(f"    回执 streams：" + compact(parsed.get('streams') or {})[:600])
        return

    # 无 spec：挑一条可控流，dry-run 展示"回写当前值"的请求（安全，不发）
    pick = None
    for feed_id, model in model_by_feed.items():
        for sid, m in model.items():
            if api.control_kind(m) in ("switch", "select", "number"):
                pick = (feed_id, sid, m)
                break
        if pick:
            break
    if not pick:
        print("    （没有可控流可供演示；用 --control FEED:STREAM:VALUE 显式下发）")
        return
    feed_id, sid, m = pick
    cur = m.get("current")
    val = cur if cur not in (None, "") else (list((m.get("options") or {"0": 0}).keys())[0])
    body = api.JdSmartClient.build_control_body(feed_id, [{"stream_id": sid, "current_value": val}])
    print(f"    [dry-run 预览] 设备 {dev_by_feed[feed_id].get('name')} 写回 {sid}={val}（当前值，不改变状态）")
    print(f"    body : {body}")
    print(f"    提示：确认前三步数据无误后，用  --control {feed_id}:{sid}:<value>  真实下发验证控制链路。")


def _match_feed(feed_s, dev_by_feed):
    """命令行 feed 容错匹配：精确 > 后缀（避开 JS 丢精度的末位差异）。"""
    if feed_s in (str(f) for f in dev_by_feed):
        return next(f for f in dev_by_feed if str(f) == feed_s)
    for f in dev_by_feed:
        if str(f).startswith(feed_s[:14]):  # 前 14 位足够区分，容忍末位精度差
            return f
    return None


# ────────────────────────────── main ──────────────────────────────
def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

    ap = argparse.ArgumentParser(
        description="JD 小京鱼 四接口端到端测试（家庭/设备/状态/控制，复用 HA 生产签名与解析）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--house", help="只测这个 houseId（默认全部已发现家庭）")
    ap.add_argument("--feed", help="只详测这台 feed_id（默认每台都测物模型+快照）")
    ap.add_argument("--control", help="真实下发一条控制：FEED:STREAM:VALUE（会改变设备状态）")
    ap.add_argument("--device-id", help="覆盖 device_id（query 用，不签名；UUID 亦可）")
    ap.add_argument("--dry-run", action="store_true", help="全程只签名打印不发送（离线验签）")
    ap.add_argument("--raw", action="store_true", help="响应原样打印")
    ap.add_argument("--secrets", default=_SECRETS, help="凭据文件（默认 jd_smart_secrets.json）")
    ap.add_argument("--timeout", type=int, default=20)
    args = ap.parse_args()

    cfg = load_secrets(args.secrets)
    client = make_client(cfg)
    device_id = resolve_device_id(cfg, args.device_id)
    tx = Transport(client, device_id, timeout=args.timeout, dry_run=args.dry_run, raw=args.raw)
    print(f"[i] device_id(query,不签名)={device_id}")
    print(f"[i] app={client.app_version}/{client.hard_platform}/{client.plat_version}"
          f"/{client.channel}/{client.plat}   tgt=<{len(client.tgt)} chars>")
    print("[i] 仅用 seg1/key/tgt/app档/device_id —— 无任何彩虹网关参数（eid/aid/ep/color_*）")

    # ① 家庭
    houses = step_houses(tx)
    if args.house:
        houses = [h for h in houses if str(h["house_id"]) == str(args.house)]
    if not houses and not args.dry_run:
        # dry-run 下家庭接口不发，构造占位以便继续演示后续请求形态
        print("\n[!] 无可用家庭（接口未返回/被 --house 过滤空）。后续步骤需要 houseId，结束。")
        return
    if not houses:  # 仅 dry-run：用占位 house 演示后续请求
        houses = [{"house_id": args.house or "1388207", "house_name": "<dry-run>", "rooms": {}}]

    # ② 设备（逐家庭）
    all_devs = []
    for h in houses:
        all_devs.extend(step_devices(tx, h))
    if not all_devs and not args.dry_run:
        print("\n[!] 选定家庭下无设备，结束。")
        return
    if not all_devs:  # dry-run 占位
        all_devs = [{"feed_id": int(args.feed) if (args.feed or "").isdigit() else 576841753861489755,
                     "house_id": houses[0]["house_id"], "name": "<dry-run>", "card_meta": {}}]

    # ③ 状态（物模型 + 快照），逐设备
    targets = all_devs
    if args.feed:
        targets = [d for d in all_devs if _match_feed(args.feed, {d["feed_id"]: d}) is not None]
        if not targets:
            print(f"\n[!] --feed {args.feed} 未匹配到已发现设备；改测全部。")
            targets = all_devs
    model_by_feed = {}
    dev_by_feed = {d["feed_id"]: d for d in all_devs}
    for d in targets:
        model_by_feed[d["feed_id"]] = step_status(tx, d)

    # ④ 控制
    step_control(tx, dev_by_feed, args.control, model_by_feed)

    print("\n[done] 端到端流程结束。若 ③ 的物模型表与 HA 设备详情界面不一致，问题在 HA 侧解析/建实体；"
          "若这里就缺流/类型错，问题在接口数据本身。")


if __name__ == "__main__":
    main()
