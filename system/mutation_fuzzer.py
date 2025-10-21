#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Code is modifed/simplified based on the Mutation-Based Fuzzer in the FuzzingBook
# "Mutation-Based Fuzzing" - a chapter of "The Fuzzing Book"
# Web site: https://www.fuzzingbook.org/html/MutationFuzzer.html

import random
from typing import Tuple, List, Callable, Set, Any

from fuzzingbook.Fuzzer import Fuzzer

# List of mutation operators
def delete_random_character(s: str) -> str:
    """Returns s with a random character deleted"""
    if s == "":
        return s

    pos = random.randint(0, len(s) - 1)
    # print("Deleting", repr(s[pos]), "at", pos)
    return s[:pos] + s[pos + 1:]

def insert_random_character(s: str) -> str:
    """Returns s with a random character inserted"""
    pos = random.randint(0, len(s))
    random_character = chr(random.randrange(32, 127))
    # print("Inserting", repr(random_character), "at", pos)
    return s[:pos] + random_character + s[pos:]

def flip_random_character(s):
    """Returns s with a random bit flipped in a random position"""
    if s == "":
        return s

    pos = random.randint(0, len(s) - 1)
    c = s[pos]
    bit = 1 << random.randint(0, 6)
    new_c = chr(ord(c) ^ bit)
    # print("Flipping", bit, "in", repr(c) + ", giving", repr(new_c))
    return s[:pos] + new_c + s[pos + 1:]

def replace_sql_token(s: str) -> str:
    """Token-level replacement:
       - SQL keyword <-> keyword
       - numbers -> boundary values
       - strings / identifiers lightly perturbed
    """
    ts = _tok(s)
    idx = [i for i,t in enumerate(ts) if not t.isspace()]
    if not idx:
        return s
    i = random.choice(idx)
    t = ts[i]
    # Keyword swap
    if t.upper() in _SQL_KW:
        alt = random.choice(_SQL_KW)
        ts[i] = alt if t.isupper() else alt.lower()
    # Integer replacement with boundary-ish values
    elif re.fullmatch(r"\d+", t):
        ts[i] = random.choice(["0","-1","1","2147483647","-2147483648","9223372036854775807","-9223372036854775808"])
    # String literal perturbation
    elif t.startswith("'") and t.endswith("'"):
        inner = t[1:-1]
        if random.random() < 0.5:
            inner = inner + "A" * random.randint(1, 30)
        else:
            if "a" in inner:
                inner = inner.replace("a", "@", 1)
            else:
                inner = inner + "!"
        ts[i] = "'" + inner + "'"
    else:
        # identifier / other: change case or append small suffix
        if random.random() < 0.5:
            ts[i] = t + random.choice(["_x","__","0"])
        else:
            ts[i] = (t.upper() if t.islower() else t.lower())
    return _unt(ts)

def duplicate_sql_clause(s: str) -> str:
    """Pick a SQL keyword token and duplicate it somewhere (simple heuristic)"""
    ts = _tok(s)
    idx = [i for i,t in enumerate(ts) if not t.isspace() and t.upper() in _SQL_KW]
    if not idx:
        return s
    i = random.choice(idx)
    t = ts[i]
    insert_pos = random.randint(0, len(ts))
    ts.insert(insert_pos, t + " ")
    return _unt(ts)

def shuffle_sql_tokens(s: str) -> str:
    """Shuffle a small contiguous span of non-whitespace tokens"""
    ts = _tok(s)
    idx = [i for i,t in enumerate(ts) if not t.isspace()]
    if len(idx) < 2:
        return s
    start = random.randint(0, len(idx) - 2)
    end = random.randint(start + 1, len(idx) - 1)
    segment_idx = idx[start:end+1]
    segment = [ts[i] for i in segment_idx]
    random.shuffle(segment)
    for j,k in enumerate(segment_idx):
        ts[k] = segment[j]
    return _unt(ts)

class MyMutationFuzzer(Fuzzer):
    """Base class for mutational fuzzing"""

    def __init__(self, seed: List[str],
                 min_mutations: int = 2,
                 max_mutations: int = 10) -> None:
        """Constructor.
        `seed` - a list of (input) strings to mutate.
        `min_mutations` - the minimum number of mutations to apply.
        `max_mutations` - the maximum number of mutations to apply.
        """
        self.seed = seed
        self.min_mutations = min_mutations
        self.max_mutations = max_mutations
        self.reset()

    def reset(self) -> None:
        """Set population to initial seed.
        To be overloaded in subclasses."""
        self.population = self.seed
        self.seed_index = 0

    def mutate(self, inp: str) -> str:
        """Return s with a random mutation applied"""
        mutators = [
	   delete_random_character,
	   insert_random_character,
	   flip_random_character
        ]
        mutator = random.choice(mutators)
        return mutator(inp)

    def create_candidate(self) -> str:
        """Create a new candidate by mutating a population member"""
        candidate = random.choice(self.population)
        trials = random.randint(self.min_mutations, self.max_mutations)
        for i in range(trials):
            candidate = self.mutate(candidate)
        return candidate

    def add_seed(self, seed: str) -> None:
        self.population.append(seed)
        print("new seed has been added to the corpus")

    def fuzz(self) -> str:
        if self.seed_index < len(self.seed):
            # Still seeding
            self.inp = self.seed[self.seed_index]
            self.seed_index += 1
        else:
            # Mutating
            self.inp = self.create_candidate()
        return self.inp
