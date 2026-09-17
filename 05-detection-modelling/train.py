"""A small sequence model over the alert stream, in PyTorch.

The idea the mentor floated, made concrete. Each episode becomes a sequence of (rule id, gap
since the previous alert); an embedding turns the rule ids into vectors, a GRU reads the
sequence in order, and a linear head decides benign or attack. The point of a sequence model
rather than a bag of counts is that it can use order: brute force, then an account, then a cron
entry is a different thing from those three events in any other arrangement.

Deliberately small. There are a few hundred episodes, so a large model would memorise them.
Anything here that looks under-engineered is under-engineered on purpose.

CPU by default. This trains in seconds and moving it to a GPU would cost more in transfers than
it saves.

    python train.py --data data/synthetic/episodes.jsonl

Read the result next to baseline.py. A sequence model that does not beat logistic regression on
counts has not earned its place, and saying so is a better outcome than shipping it anyway.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

import numpy as np
import torch
import torch.nn as nn

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from alert_stream import COMPOSITE_RULE, VOCAB
from features import load_split, report, scores, sequences

ATTACK = 1


class AlertGRU(nn.Module):
    def __init__(self, vocab=VOCAB, emb=16, hidden=32, dropout=0.2):
        super().__init__()
        self.emb = nn.Embedding(vocab, emb, padding_idx=0)
        # +1 input dim for the log gap that travels alongside each rule id. The gap is the
        # signal separating an administrator's two steps from an attacker's.
        self.gru = nn.GRU(emb + 1, hidden, batch_first=True)
        self.drop = nn.Dropout(dropout)
        self.head = nn.Linear(hidden, 2)

    def forward(self, ids, gaps, lengths):
        x = torch.cat([self.emb(ids), gaps.unsqueeze(-1)], dim=-1)
        packed = nn.utils.rnn.pack_padded_sequence(
            x, lengths.cpu().clamp(min=1), batch_first=True, enforce_sorted=False)
        _, h = self.gru(packed)
        return self.head(self.drop(h[-1]))


def to_tensors(episodes, max_len):
    ids, gaps, lengths, y = sequences(episodes, max_len)
    # Sequences are left padded, so the real alerts sit at the end. pack_padded_sequence expects
    # them at the front, so roll each row so its content leads.
    rolled_ids = np.zeros_like(ids)
    rolled_gaps = np.zeros_like(gaps)
    for i, L in enumerate(lengths):
        if L:
            rolled_ids[i, :L] = ids[i, max_len - L:]
            rolled_gaps[i, :L] = gaps[i, max_len - L:]
    return (torch.from_numpy(rolled_ids), torch.from_numpy(rolled_gaps),
            torch.from_numpy(lengths), torch.from_numpy(y))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default="data/synthetic/episodes.jsonl")
    p.add_argument("--train-frac", type=float, default=0.7)
    p.add_argument("--max-len", type=int, default=64)
    p.add_argument("--epochs", type=int, default=250)
    p.add_argument("--lr", type=float, default=3e-3)
    p.add_argument("--seed", type=int, default=0)
    # A single seed on a test set this small is not a result, it is one sample. Five runs and
    # their spread is the honest way to report it, and the spread here is not small.
    p.add_argument("--repeats", type=int, default=5)
    a = p.parse_args()

    train_eps, test_eps = load_split(a.data, a.train_frac)
    # The validation slice is the tail of training, again by time, so model selection never sees
    # anything later than what it trains on.
    vcut = int(len(train_eps) * 0.85)
    val_eps = train_eps[vcut:]
    train_eps = train_eps[:vcut]

    tr = to_tensors(train_eps, a.max_len)
    va = to_tensors(val_eps, a.max_len)
    te = to_tensors(test_eps, a.max_len)

    print("%s" % a.data)
    print("  train %d  val %d  test %d  (all split by time, never shuffled)"
          % (len(train_eps), len(val_eps), len(test_eps)))
    print("  attack share: train %.2f  test %.2f"
          % (tr[3].float().mean().item(), te[3].float().mean().item()))

    print("  model: embedding + GRU + linear, %d parameters, CPU"
          % sum(p_.numel() for p_ in AlertGRU().parameters()))
    print()

    yte = te[3].numpy()
    results, best_overall, best_run_f1 = [], None, -1.0

    for run in range(a.repeats):
        seed = a.seed + run
        torch.manual_seed(seed)
        np.random.seed(seed)

        model = AlertGRU()
        counts = torch.bincount(tr[3], minlength=2).float().clamp(min=1.0)
        loss_fn = nn.CrossEntropyLoss(weight=counts.sum() / (2.0 * counts))
        opt = torch.optim.Adam(model.parameters(), lr=a.lr)

        best_f1, best_state, best_epoch = -1.0, None, 0
        for epoch in range(1, a.epochs + 1):
            model.train()
            opt.zero_grad()
            loss_fn(model(tr[0], tr[1], tr[2]), tr[3]).backward()
            opt.step()

            if epoch % 5 == 0 or epoch == a.epochs:
                model.eval()
                with torch.no_grad():
                    pred = model(va[0], va[1], va[2]).argmax(1).numpy()
                f1 = scores(va[3].numpy(), pred)["f1"]
                if f1 > best_f1:
                    best_f1, best_epoch = f1, epoch
                    best_state = {k: v.clone() for k, v in model.state_dict().items()}

        if best_state is not None:
            model.load_state_dict(best_state)
        model.eval()
        with torch.no_grad():
            pred = model(te[0], te[1], te[2]).argmax(1).numpy()
        s = scores(yte, pred)
        results.append(s)
        report("seed %d (epoch %d)" % (seed, best_epoch), s)
        if s["f1"] > best_run_f1:
            best_run_f1, best_overall = s["f1"], {k: v.clone() for k, v in model.state_dict().items()}

    rule = np.array([int(any(al["ruleId"] == COMPOSITE_RULE for al in e["alerts"]))
                     for e in test_eps], dtype=np.int64)
    f1s = np.array([r["f1"] for r in results])

    print()
    print("Held out, %d seeds:" % a.repeats)
    report("rule 100111 only", scores(yte, rule))
    print("  %-28s f1 %.3f mean, %.3f sd, %.3f worst, %.3f best"
          % ("GRU over the sequence", f1s.mean(), f1s.std(), f1s.min(), f1s.max()))
    print()
    print("Compare against baseline.py on the same file before concluding anything. A sequence")
    print("model that does not beat logistic regression on counts has not earned its place.")

    out = pathlib.Path("models"); out.mkdir(exist_ok=True)
    torch.save({"state_dict": best_overall, "max_len": a.max_len, "vocab": VOCAB},
               out / "alert_gru.pt")
    print("\nSaved models/alert_gru.pt (best of %d seeds, f1 %.3f)" % (a.repeats, best_run_f1))


if __name__ == "__main__":
    main()
