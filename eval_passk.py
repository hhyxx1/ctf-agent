"""Pass@k 评估（agent book chapter7）：对单题跑 k 次，统计解题成功率。

用法（会真实启环境 + 烧 token，k 建议 1-3）：
    .venv/bin/python eval_passk.py 10662 -k 3
"""
import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def passk_slab(ex_id: int, k: int) -> float:
    """对 slab 平台某题跑 k 次 solve_challenge，统计成功比例"""
    from slab_match_solver import solve_challenge, _load_progress
    from utils.slab_match_api import SlabMatchAPI

    api = SlabMatchAPI()
    progress = _load_progress()
    ch = {"exercise_id": ex_id, "name": f"eval-{ex_id}", "category": "", "has_solved": False}
    ok = 0
    for i in range(k):
        try:
            r = solve_challenge(api, ch, progress)
            st = r.get("status", "failed")
            print(f"  run {i+1}/{k}: {st}")
            if st in ("solved", "partial"):
                ok += 1
        except Exception as e:
            print(f"  run {i+1}/{k}: 异常 {e}")
    return ok / k


def passk_tsec(unique_code: str, k: int) -> float:
    """对 tsecbench 某题跑 k 次（单题函数），统计成功比例"""
    from tsecbench_solver import solve_one  # 单题解题函数（如存在）
    ok = 0
    for i in range(k):
        try:
            r = solve_one(unique_code)
            st = "solved" if r else "failed"
            print(f"  run {i+1}/{k}: {st}")
            if r:
                ok += 1
        except Exception as e:
            print(f"  run {i+1}/{k}: 异常 {e}")
    return ok / k


def main():
    ap = argparse.ArgumentParser(description="Pass@k 评估（多次运行统计解题成功率）")
    ap.add_argument("target", help="题目 ID（slab: 数字；tsecbench: unique_code）")
    ap.add_argument("-k", type=int, default=3, help="运行次数（默认 3，越小越省 token）")
    ap.add_argument("--platform", default="slab", choices=["slab", "tsecbench"])
    args = ap.parse_args()

    if args.platform == "slab":
        p = passk_slab(int(args.target), args.k)
    else:
        p = passk_tsec(args.target, args.k)
    print(f"\nPass@{args.k} ({args.platform} {args.target}) = {p:.2f}")


if __name__ == "__main__":
    main()
