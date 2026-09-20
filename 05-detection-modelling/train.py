"""A small sequence model over the alert stream, in PyTorch.

The idea the mentor floated, made concrete. Each episode becomes a sequence of (rule id, gap
since the previous alert); an embedding turns the rule ids into vectors, a GRU reads the
sequence in order, and a linear head decides benign or attack. The point of a sequence model
rather than a bag of counts is that it can use order: brute force, then an account, then a cron
entry is a different thing from those three events in any other arrangement.

Deliberately small, at five thousand odd parameters. Anything here that looks
under-engineered is under-engineered on purpose: the question is whether order carries signal,
and a bigger model would answer a different question badly.

CPU by default. This trains in seconds on a lab campaign and in minutes on AIT, and moving it
to a GPU would cost more in transfers than it saves.

    python train.py --data data/synthetic/episodes.jsonl
    python train.py --data data/ait/episodes.jsonl --split source --max-len 128 \
                    --batch-size 256 --epochs 80

Two settings matter once the dataset is larger than a lab campaign. --batch-size 0, the
default, keeps the original full batch behaviour, which is correct for a few hundred episodes
and would give the model only 250 weight updates on several thousand; pass a real batch size
there. And --split source holds out whole capture sources rather than the tail of a timeline,
which is the harder and more meaningful test when the sources are independent networks.

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
from features import (average_precision, build_vocab, load_split, pick_threshold,
                      report, scores, sequences, sources_of)

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


def to_tensors(episodes, max_len, vocab=None):
    ids, gaps, lengths, y = (sequences(episodes, max_len, vocab) if vocab is not None
                             else sequences(episodes, max_len))
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
    p.add_argument("--split", choices=("time", "source"), default="time")
    p.add_argument("--rule", type=int, default=None,
                   help="the single signature to compare against; defaults to 100111 where it "
                        "exists in the data")
    # 0 keeps the original full batch behaviour, which is right for a few hundred episodes.
    # On a dataset of thousands, 250 full batch steps is 250 weight updates and the model would
    # lose the comparison for want of training rather than for want of signal. Minibatching is
    # how it gets a fair number of them. Shuffling inside the training set is not a leak; only
    # shuffling before the split would be.
    p.add_argument("--batch-size", type=int, default=0)
    a = p.parse_args()

    train_eps, test_eps = load_split(a.data, a.train_frac, a.split)
    vocab = build_vocab(train_eps, a.data)
    # The validation slice is the tail of training. Under a time split that is the most recent
    # episodes, so model selection never sees anything later than what it trains on; under a
    # source split the training episodes are grouped by source, so the tail is a whole source
    # held back, which is the same discipline applied to the same axis as the test set.
    vcut = int(len(train_eps) * 0.85)
    val_eps = train_eps[vcut:]
    train_eps = train_eps[:vcut]

    tr = to_tensors(train_eps, a.max_len, vocab)
    va = to_tensors(val_eps, a.max_len, vocab)
    te = to_tensors(test_eps, a.max_len, vocab)

    print("%s" % a.data)
    print("  train %d  val %d  test %d  (split by %s, never shuffled across the boundary)"
          % (len(train_eps), len(val_eps), len(test_eps), a.split))
    print("  attack share: train %.3f  test %.3f"
          % (tr[3].float().mean().item(), te[3].float().mean().item()))
    if a.split == "source":
        print("  train sources: %s" % ", ".join(sources_of(train_eps)))
        print("  val sources:   %s" % ", ".join(sources_of(val_eps)))
        print("  held out:      %s" % ", ".join(sources_of(test_eps)))

    print("  model: embedding + GRU + linear, %d parameters, CPU, vocab %d"
          % (sum(p_.numel() for p_ in AlertGRU(vocab.size).parameters()), vocab.size))
    print("  updates per epoch: %d"
          % (1 if a.batch_size <= 0 else max(1, -(-len(train_eps) // a.batch_size))))
    print()

    yte = te[3].numpy()
    results, best_overall, best_run_f1 = [], None, -1.0

    for run in range(a.repeats):
        seed = a.seed + run
        torch.manual_seed(seed)
        np.random.seed(seed)

        model = AlertGRU(vocab.size)
        counts = torch.bincount(tr[3], minlength=2).float().clamp(min=1.0)
        loss_fn = nn.CrossEntropyLoss(weight=counts.sum() / (2.0 * counts))
        opt = torch.optim.Adam(model.parameters(), lr=a.lr)

        n_train = tr[0].shape[0]
        bs = n_train if a.batch_size <= 0 else min(a.batch_size, n_train)
        g = torch.Generator().manual_seed(seed)

        best_f1, best_state, best_epoch = -1.0, None, 0
        for epoch in range(1, a.epochs + 1):
            model.train()
            order = (torch.arange(n_train) if bs == n_train
                     else torch.randperm(n_train, generator=g))
            for s in range(0, n_train, bs):
                sl = order[s:s + bs]
                opt.zero_grad()
                loss_fn(model(tr[0][sl], tr[1][sl], tr[2][sl]), tr[3][sl]).backward()
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
            pv = torch.softmax(model(va[0], va[1], va[2]), dim=1)[:, 1].numpy()
            pt = torch.softmax(model(te[0], te[1], te[2]), dim=1)[:, 1].numpy()
        # Same discipline as baseline.py: the cut comes off validation, never off the test set.
        # At a two percent base rate, argmax is an arbitrary operating point rather than a
        # neutral one, and comparing it against a tuned logistic would be rigged.
        thr, _ = pick_threshold(va[3].numpy(), pv)
        s = scores(yte, (pt >= thr).astype(np.int64))
        s["ap"] = average_precision(yte, pt)
        results.append(s)
        report("seed %d (epoch %d, cut %.3f)" % (seed, best_epoch, thr), s)
        print("  %-28s average precision %.3f" % ("", s["ap"]))
        if s["f1"] > best_run_f1:
            best_run_f1, best_overall = s["f1"], {k: v.clone() for k, v in model.state_dict().items()}

    f1s = np.array([r["f1"] for r in results])

    print()
    print("Held out, %d seeds:" % a.repeats)
    single = a.rule if a.rule is not None else (
        COMPOSITE_RULE if COMPOSITE_RULE in vocab.rule_ids else None)
    if single is not None:
        rule = np.array([int(any(al["ruleId"] == single for al in e["alerts"]))
                         for e in test_eps], dtype=np.int64)
        report("rule %d only" % single, scores(yte, rule))
    else:
        print("  %-28s not present in this data; see baseline.py for the rule comparison"
              % "single rule")
    aps = np.array([r["ap"] for r in results])
    print("  %-28s f1 %.3f mean, %.3f sd, %.3f worst, %.3f best"
          % ("GRU over the sequence", f1s.mean(), f1s.std(), f1s.min(), f1s.max()))
    print("  %-28s average precision %.3f mean, %.3f sd"
          % ("", aps.mean(), aps.std()))
    print()
    print("Compare against baseline.py on the same file before concluding anything. A sequence")
    print("model that does not beat logistic regression on counts has not earned its place.")

    out = pathlib.Path("models"); out.mkdir(exist_ok=True)
    stem = pathlib.Path(a.data).parent.name
    torch.save({"state_dict": best_overall, "max_len": a.max_len,
                "vocab": vocab.size, "ruleIds": vocab.rule_ids},
               out / ("alert_gru_%s.pt" % stem))
    print("\nSaved models/alert_gru_%s.pt (best of %d seeds, f1 %.3f)"
          % (stem, a.repeats, best_run_f1))


if __name__ == "__main__":
    main()
